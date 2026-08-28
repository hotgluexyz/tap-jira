"""Unit tests for the pure logic ported from the pre-SDK tap."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from tap_jira.client import JiraOffsetStream, JiraPagedStream, load_schema
from tap_jira.streams import (
    DependencyException,
    IssuePrioritiesStream,
    IssuesStream,
    StatusesStream,
    UsersStream,
    WorklogsBookmarkError,
    raise_if_bookmark_cannot_advance,
    validate_dependencies,
)


def _response(payload):
    response = Mock()
    response.json.return_value = payload
    return response


def _worklogs(count: int, updated: str | list[str]) -> list[dict]:
    if isinstance(updated, str):
        updated = [updated] * count
    return [{"id": str(i), "updated": u} for i, u in enumerate(updated)]


class TestRaiseIfBookmarkCannotAdvance:
    """The 1000-record cap combined with `<=` `since` semantics."""

    def test_full_page_all_identical_raises(self):
        with pytest.raises(WorklogsBookmarkError):
            raise_if_bookmark_cannot_advance(_worklogs(1000, "2026-01-01T00:00:00.000+0000"))

    def test_one_below_full_page_all_identical_is_fine(self):
        raise_if_bookmark_cannot_advance(_worklogs(999, "2026-01-01T00:00:00.000+0000"))

    def test_full_page_with_distinct_timestamps_is_fine(self):
        stamps = [f"2026-01-01T00:00:00.{i:03d}+0000" for i in range(1000)]
        raise_if_bookmark_cannot_advance(_worklogs(1000, stamps))

    def test_mixed_offsets_compare_as_instants(self):
        raise_if_bookmark_cannot_advance(
            _worklogs(2, ["2026-01-01T07:00:00.000-0500", "2026-01-01T12:00:00.000+0000"])
        )


class TestPagedStreamPaging:
    """`startAt` paging over responses nesting records under `values`."""

    @staticmethod
    def _token(payload, previous=None, page_size=50):
        stream = Mock()
        stream.page_size = page_size
        return JiraPagedStream.get_next_page_token(stream, _response(payload), previous)

    def test_full_page_advances_by_max_results(self):
        payload = {"values": [{}] * 50, "maxResults": 50}
        assert self._token(payload) == 50
        assert self._token(payload, previous=50) == 100

    def test_partial_page_stops(self):
        assert self._token({"values": [{}] * 20, "maxResults": 50}) is None

    def test_empty_page_stops(self):
        assert self._token({"values": [], "maxResults": 50}) is None

    def test_missing_max_results_falls_back_to_requested_page_size(self):
        # We send maxResults, so a response that omits it is compared against what
        # we asked for: a short page ends the walk, a full page continues.
        assert self._token({"values": [{}] * 25}) is None
        assert self._token({"values": [{}] * 50}) == 50

    def test_missing_values_key_stops(self):
        assert self._token({}) is None

    def test_response_max_results_overrides_the_requested_page_size(self):
        # Jira may apply a smaller page size than requested; trust the response.
        assert self._token({"values": [{}] * 20, "maxResults": 20}, page_size=50) == 20

    def test_is_last_stops_even_on_a_full_page(self):
        # Jira's search endpoints return isLast; it is authoritative.
        assert self._token({"values": [{}] * 50, "maxResults": 50, "isLast": True}) is None

    def test_is_last_false_keeps_paging(self):
        assert self._token({"values": [{}] * 50, "maxResults": 50, "isLast": False}) == 50

    def test_walks_multiple_pages_to_completion(self):
        pages = [
            {"values": [{}] * 50, "maxResults": 50, "isLast": False},
            {"values": [{}] * 50, "maxResults": 50, "isLast": False},
            {"values": [{}] * 12, "maxResults": 50, "isLast": True},
        ]
        token, offsets = None, []
        for page in pages:
            token = self._token(page, token)
            offsets.append(token)
        assert offsets == [50, 100, None]


class TestOffsetStreamPaging:
    """`startAt` paging over endpoints returning a bare JSON array."""

    @staticmethod
    def _token(payload, previous=None, page_size=50):
        stream = Mock()
        stream.page_size = page_size
        return JiraOffsetStream.get_next_page_token(stream, _response(payload), previous)

    def test_full_page_advances(self):
        assert self._token([{}] * 50) == 50
        assert self._token([{}] * 50, previous=50) == 100

    def test_short_page_stops(self):
        assert self._token([{}] * 20) is None

    def test_empty_page_stops(self):
        assert self._token([]) is None

    def test_envelope_response_stops_rather_than_looping(self):
        # Defensive: this endpoint family returns a list, not a dict.
        assert self._token({"values": [{}] * 50}) is None

    def test_walks_multiple_pages_to_completion(self):
        pages = [[{}] * 50, [{}] * 50, [{}] * 7]
        token, offsets = None, []
        for page in pages:
            token = self._token(page, token)
            offsets.append(token)
        assert offsets == [50, 100, None]

    def test_url_params_send_offset_and_page_size(self):
        stream = Mock()
        stream.page_size = 50
        assert JiraOffsetStream.get_url_params(stream, None, None) == {
            "startAt": 0,
            "maxResults": 50,
        }
        assert JiraOffsetStream.get_url_params(stream, None, 100) == {
            "startAt": 100,
            "maxResults": 50,
        }


class TestStreamResponseShapes:
    """Guards the two different response envelopes these endpoints use.

    /rest/api/2/users/search returns a bare JSON array, while the /statuses/search
    and /priority/search endpoints wrap records in `values`. Giving `users` the
    envelope jsonpath would silently emit zero records.
    """

    def test_users_reads_a_bare_array(self):
        assert issubclass(UsersStream, JiraOffsetStream)
        assert UsersStream.records_jsonpath == "$[*]"

    @pytest.mark.parametrize("stream", [StatusesStream, IssuePrioritiesStream])
    def test_search_endpoints_read_the_values_envelope(self, stream):
        assert issubclass(stream, JiraPagedStream)
        assert stream.records_jsonpath == "$.values[*]"


class TestValidateDependencies:
    """Ported from the pre-SDK tap's validate_dependencies()."""

    @staticmethod
    def _tap(*selected: str):
        tap = Mock()
        tap.streams = {
            name: Mock(selected=name in selected)
            for name in (
                "projects",
                "versions",
                "components",
                "issues",
                "changelogs",
                "issue_comments",
                "issue_transitions",
            )
        }
        return tap

    @pytest.mark.parametrize(
        ("selected", "expected"),
        [
            (("changelogs",), "Changelog"),
            (("issue_comments",), "Issue Comments"),
            (("issue_transitions",), "Issue Transitions"),
        ],
    )
    def test_issue_substream_without_issues_raises(self, selected, expected):
        with pytest.raises(DependencyException, match=expected):
            validate_dependencies(self._tap(*selected))

    @pytest.mark.parametrize("selected", [("versions",), ("components",)])
    def test_project_children_need_no_check(self, selected):
        # The SDK syncs an unselected parent to drive a selected child.
        validate_dependencies(self._tap(*selected))

    @pytest.mark.parametrize(
        "selected",
        [
            ("issues", "changelogs", "issue_comments", "issue_transitions"),
            ("projects",),
            (),
        ],
    )
    def test_satisfied_dependencies_pass(self, selected):
        validate_dependencies(self._tap(*selected))

    def test_all_unmet_dependencies_are_reported_together(self):
        with pytest.raises(DependencyException) as exc:
            validate_dependencies(self._tap("changelogs", "issue_comments"))
        assert "Changelog" in str(exc.value)
        assert "Issue Comments" in str(exc.value)


class TestLoadSchema:
    """Schemas are reused from the pre-SDK tap and use bare-name `$ref`s."""

    @pytest.mark.parametrize(
        "name", ["issues", "projects", "worklogs", "changelogs", "issue_comments"]
    )
    def test_refs_are_fully_inlined(self, name):
        schema = load_schema(name)
        assert "$ref" not in json.dumps(schema)
        assert "definitions" not in schema

    def test_nested_ref_resolves_to_the_definition(self):
        author = load_schema("worklogs")["properties"]["author"]
        assert author["title"] == "User"
        assert "properties" in author

    def test_schema_without_definitions_is_returned_as_is(self):
        assert "properties" in load_schema("resolutions")


class TestWorklogsLoopTermination:
    """The `since` cursor must move forward or the loop must stop.

    `/worklog/updated` uses `<=` semantics, so a bookmark that does not advance
    re-requests an identical page forever. `/worklog/list` omits deleted worklogs,
    so a full id page can return fewer records, staying below the 1000-record
    threshold that `raise_if_bookmark_cannot_advance` guards.
    """

    @staticmethod
    def _stream(ids_pages, worklog_pages):
        from tap_jira.streams import WorklogsStream

        stream = Mock(spec=WorklogsStream)
        stream.logger = Mock()
        stream.config = {"start_date": "2026-01-01T00:00:00Z"}
        stream.get_starting_timestamp = Mock(return_value=None)
        stream._fetch_ids = Mock(side_effect=ids_pages)
        stream._fetch_worklogs = Mock(side_effect=worklog_pages)
        return stream

    def test_stops_when_bookmark_cannot_advance(self):
        from tap_jira.streams import WorklogsStream

        stamp = "2026-01-01T00:00:00.000+0000"
        ids_pages = [{"values": [{"worklogId": i} for i in range(1000)], "lastPage": False}] * 5
        worklog_pages = [_worklogs(800, stamp)] * 5

        stream = self._stream(ids_pages, worklog_pages)
        records = list(WorklogsStream.get_records(stream, None))

        assert len(records) == 800
        assert stream._fetch_ids.call_count == 1
        assert stream.logger.warning.called

    def test_advancing_bookmark_keeps_paging(self):
        from tap_jira.streams import WorklogsStream

        ids_pages = [
            {"values": [{"worklogId": 1}], "lastPage": False},
            {"values": [{"worklogId": 2}], "lastPage": True},
        ]
        worklog_pages = [
            _worklogs(1, "2026-01-02T00:00:00.000+0000"),
            _worklogs(1, "2026-01-03T00:00:00.000+0000"),
        ]
        stream = self._stream(ids_pages, worklog_pages)
        records = list(WorklogsStream.get_records(stream, None))

        assert len(records) == 2
        assert stream._fetch_ids.call_count == 2


class TestIssuesCursorPaging:
    """`nextPageToken` paging over /rest/api/3/search/jql."""

    @staticmethod
    def _token(payload, previous=None):
        return IssuesStream.get_next_page_token(Mock(), _response(payload), previous)

    def test_returns_the_cursor(self):
        assert self._token({"nextPageToken": "abc"}) == "abc"

    def test_is_last_stops(self):
        assert self._token({"nextPageToken": "abc", "isLast": True}) is None

    def test_missing_cursor_stops(self):
        assert self._token({}) is None

    def test_repeated_cursor_stops(self):
        # An API echoing the same cursor would otherwise page forever.
        assert self._token({"nextPageToken": "abc"}, previous="abc") is None

    def test_walks_multiple_pages_to_completion(self):
        pages = [{"nextPageToken": "p2"}, {"nextPageToken": "p3"}, {"isLast": True}]
        token, seen = None, []
        for page in pages:
            token = self._token(page, token)
            seen.append(token)
        assert seen == ["p2", "p3", None]
