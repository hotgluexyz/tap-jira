"""Stream type classes for tap-jira."""

from __future__ import annotations

from collections.abc import Iterable
from functools import cached_property
from typing import Any, ClassVar

import pytz
import requests
from hotglue_singer_sdk import Stream
from hotglue_singer_sdk.exceptions import FatalAPIError, RetriableAPIError
from singer import utils
from typing_extensions import override

from tap_jira.client import JiraPagedStream, JiraStream, load_schema


class DependencyException(Exception):
    """Raised when a selected stream depends on another that is not selected."""


def validate_dependencies(tap) -> None:
    """Fail if a stream is selected without the stream that produces its data."""
    errs = []
    msg_tmpl = "Unable to extract {0} data. To receive {0} data, you also need to select {1}."

    def selected(name: str) -> bool:
        stream = tap.streams.get(name)
        return bool(stream and stream.selected)

    # The issues sub-streams are written directly by IssuesStream so they do still depend on `issues` being selected.
    if not selected("issues"):
        if selected("changelogs"):
            errs.append(msg_tmpl.format("Changelog", "Issues"))
        if selected("issue_comments"):
            errs.append(msg_tmpl.format("Issue Comments", "Issues"))
        if selected("issue_transitions"):
            errs.append(msg_tmpl.format("Issue Transitions", "Issues"))
    if errs:
        raise DependencyException(" ".join(errs))


class WorklogsBookmarkError(Exception):
    """Raised when the worklogs `updated` bookmark cannot safely advance."""


def raise_if_bookmark_cannot_advance(worklogs: list[dict]) -> None:
    # Worklogs can only be queried with a `since` timestamp and
    # provides no way to page through the results. The `since`
    # timestamp has <=, not <, semantics. It also caps the response at
    # 1000 objects. Because of this, if we ever see a page of 1000
    # worklogs that all have the same `updated` timestamp, we cannot
    # tell whether we in fact got all the updates and so we need to
    # raise.
    #
    # That said, a page of 999 worklogs that all have the same
    # timestamp is fine. That just means that 999 worklogs were
    # updated at the same timestamp but that we did, in fact, get them
    # all.
    #
    # The behavior, then, always resyncs the latest `updated`
    # timestamp, no matter how many results are there. If you have 500
    # worklogs updated at T1 and 999 worklogs updated at T2 and
    # `last_updated` is set to T1, the first trip through this will
    # see 1000 items, 500 of which have `updated==T1` and 500 of which
    # have `updated==T2`. Then, `last_updated` is set to T2 and due to
    # the <= semantics, you grab the 999 T2 worklogs which passes this
    # function because there's less than 1000 worklogs of
    # `updated==T2`.
    #
    # OTOH, if you have 1 worklog with `updated==T1` and 1000 worklogs
    # with `updated==T2`, first trip you see 1 worklog at T1 and 999
    # at T2 which this code will think is fine, but second trip
    # through you'll see 1000 worklogs at T2 which will fail
    # validation (because we can't tell whether there would be more
    # that should've been returned).
    worklog_updatedes = [utils.strptime_to_utc(w["updated"]) for w in worklogs]
    min_updated = min(worklog_updatedes)
    max_updated = max(worklog_updatedes)
    if len(worklogs) == 1000 and min_updated == max_updated:
        raise WorklogsBookmarkError(
            "Worklogs bookmark can't safely advance."
            f"Every `updated` field is `{worklog_updatedes[0]}`"
        )


class ProjectsStream(JiraStream):
    """Stream for ``projects``."""

    name = "projects"
    path = "/rest/api/2/project"
    primary_keys: ClassVar[list[str]] = ["id"]
    replication_key = None
    schema = load_schema("projects")

    @override
    def get_url_params(self, context: dict | None, next_page_token: Any | None) -> dict[str, Any]:
        return {"expand": "description,lead,url,projectKeys,issueTypes"}

    @override
    def get_child_context(self, record: dict, context: dict | None) -> dict:
        return {"project_id": record["id"]}

    @override
    def post_process(self, row: dict, context: dict | None = None) -> dict | None:
        row.pop("versions", None)
        return row


class VersionsStream(JiraPagedStream):
    name = "versions"
    path = "/rest/api/2/project/{project_id}/version"
    primary_keys: ClassVar[list[str]] = ["id"]
    replication_key = None
    parent_stream_type = ProjectsStream
    order_by = "sequence"
    schema = load_schema("versions")


class ComponentsStream(JiraPagedStream):
    name = "components"
    path = "/rest/api/2/project/{project_id}/component"
    primary_keys: ClassVar[list[str]] = ["id"]
    replication_key = None
    parent_stream_type = ProjectsStream
    schema = load_schema("components")


class ProjectTypesStream(JiraStream):
    name = "project_types"
    path = "/rest/api/2/project/type"
    primary_keys: ClassVar[list[str]] = ["key"]
    replication_key = None
    schema = load_schema("project_types")

    @override
    def post_process(self, row: dict, context: dict | None = None) -> dict | None:
        row.pop("icon", None)
        return row


class ProjectCategoriesStream(JiraStream):
    name = "project_categories"
    path = "/rest/api/2/projectCategory"
    primary_keys: ClassVar[list[str]] = ["id"]
    replication_key = None
    schema = load_schema("project_categories")


class IssueTypesStream(JiraStream):
    name = "issue_types"
    path = "/rest/api/2/issuetype"
    primary_keys: ClassVar[list[str]] = ["id"]
    replication_key = None
    schema = load_schema("issue_types")


class ResolutionsStream(JiraStream):
    name = "resolutions"
    path = "/rest/api/2/resolution"
    primary_keys: ClassVar[list[str]] = ["id"]
    replication_key = None
    schema = load_schema("resolutions")


class RolesStream(JiraStream):
    name = "roles"
    path = "/rest/api/2/role"
    primary_keys: ClassVar[list[str]] = ["id"]
    replication_key = None
    schema = load_schema("roles")


class UsersStream(JiraStream):
    # Single request, no paging -- matches the pre-SDK tap, which called this
    # endpoint once via the base Stream.sync(). Paginating it would change the
    # record set this stream has always produced; tracked separately.
    name = "users"
    path = "/rest/api/2/users/search"
    primary_keys: ClassVar[list[str]] = ["accountId"]
    replication_key = None
    schema = load_schema("users")


class StatusesStream(JiraStream):
    # Single request, no paging -- matches the pre-SDK tap, which called this
    # endpoint once via the base Stream.sync(). Paginating it would change the
    # record set this stream has always produced; tracked separately.
    name = "statuses"
    path = "/rest/api/2/statuses/search"
    primary_keys: ClassVar[list[str]] = ["id"]
    replication_key = None
    records_jsonpath = "$.values[*]"
    schema = load_schema("statuses")


class IssuePrioritiesStream(JiraStream):
    # Single request, no paging -- matches the pre-SDK tap, which called this
    # endpoint once via the base Stream.sync(). Paginating it would change the
    # record set this stream has always produced; tracked separately.
    name = "issue_priorities"
    path = "/rest/api/2/priority/search"
    primary_keys: ClassVar[list[str]] = ["id"]
    replication_key = None
    records_jsonpath = "$.values[*]"
    schema = load_schema("issue_priorities")


class IssueSubStream(Stream):
    replication_key = None
    _schema_emitted = False

    @override
    def get_records(self, context: dict | None) -> Iterable[dict]:
        self._schema_emitted = True
        return iter(())


class IssueCommentsStream(IssueSubStream):
    name = "issue_comments"
    primary_keys: ClassVar[list[str]] = ["id"]
    schema = load_schema("issue_comments")

    @override
    def post_process(self, row: dict, context: dict | None = None) -> dict | None:
        """Coerce rich-text fields to strings, as the pre-SDK tap did."""
        for field in ("body", "renderedBody"):
            value = row.get(field)
            if value is not None and not isinstance(value, str):
                row[field] = str(value)
        return row


class ChangelogsStream(IssueSubStream):
    name = "changelogs"
    primary_keys: ClassVar[list[str]] = ["id"]
    schema = load_schema("changelogs")


class IssueTransitionsStream(IssueSubStream):
    name = "issue_transitions"
    primary_keys: ClassVar[list[str]] = ["id"]
    schema = load_schema("issue_transitions")


class IssuesStream(JiraStream):
    name = "issues"
    path = "/rest/api/3/search/jql"
    primary_keys: ClassVar[list[str]] = ["id"]
    replication_key = None
    records_jsonpath = "$.issues[*]"
    schema = load_schema("issues")

    @cached_property
    def timezone(self) -> str:
        try:
            response = self._request(
                self.build_prepared_request(
                    method="GET",
                    url=f"{self.url_base}/rest/api/2/myself",
                    headers=self.http_headers,
                ),
                None,
            )
            if response.status_code != 200:
                raise RuntimeError(f"{response.status_code} from /myself")
            return response.json()["timeZone"]
        except (
            FatalAPIError,
            RetriableAPIError,
            requests.RequestException,
            RuntimeError,
            KeyError,
        ) as ex:
            # /myself needs the read:jira-user scope, which a token scoped only to
            # jira-work will not have. Fall back to UTC rather than failing the sync.
            self.logger.warning(
                f"Could not read the account timezone ({ex}); using UTC for the jql filter."
            )
            return "UTC"

    @property
    def starting_updated(self):
        bookmark = self.stream_state.get("replication_key_value")
        return utils.strptime_to_utc(bookmark or self.config["start_date"])

    @override
    def get_url_params(self, context: dict | None, next_page_token: Any | None) -> dict[str, Any]:
        start_date = self.starting_updated.astimezone(pytz.timezone(self.timezone)).strftime(
            "%Y-%m-%d %H:%M"
        )
        params: dict[str, Any] = {
            "fields": "*all",
            "expand": "changelog,transitions",
            "validateQuery": "strict",
            "jql": f"updated >= '{start_date}' order by updated asc",
        }
        if next_page_token:
            params["nextPageToken"] = next_page_token
        return params

    @override
    def get_next_page_token(self, response: Any, previous_token: Any | None) -> Any | None:
        data = response.json()
        if data.get("isLast"):
            return None
        return data.get("nextPageToken") or None

    @override
    def get_records(self, context: dict | None) -> Iterable[dict]:
        latest = None
        for record in super().get_records(context):
            updated = (record.get("fields") or {}).get("updated")
            if updated:
                latest = utils.strptime_to_utc(updated)
            yield record
        if latest:
            self.stream_state["replication_key_value"] = utils.strftime(latest)

    def _emit_substream(self, name: str, records: list[dict], issue_id: str) -> None:
        if not records:
            return
        stream = self._tap.streams.get(name)
        if stream is None or not stream.selected:
            return
        if not stream._schema_emitted:
            stream._write_schema_message()
            stream._schema_emitted = True
        for record in records:
            record["issueId"] = issue_id
            processed = stream.post_process(record)
            if processed is not None:
                stream._write_record_message(processed)

    @override
    def post_process(self, row: dict, context: dict | None = None) -> dict | None:
        fields = row.get("fields") or {}
        self._emit_substream(
            "issue_comments", (fields.pop("comment", None) or {}).get("comments") or [], row["id"]
        )
        self._emit_substream(
            "changelogs", (row.pop("changelog", None) or {}).get("histories") or [], row["id"]
        )
        self._emit_substream("issue_transitions", row.pop("transitions", None) or [], row["id"])
        fields.pop("worklog", None)
        fields.pop("operations", None)
        return row


class WorklogsStream(JiraStream):
    name = "worklogs"
    path = "/rest/api/2/worklog/updated"
    primary_keys: ClassVar[list[str]] = ["id"]
    replication_key = "updated"
    schema = load_schema("worklogs")

    def _fetch_ids(self, last_updated) -> dict:
        # since_ts uses millisecond precision
        since_ts = int(last_updated.timestamp()) * 1000
        response = self._request(
            self.build_prepared_request(
                method="GET",
                url=f"{self.url_base}{self.path}",
                headers=self.http_headers,
                params={"since": since_ts},
            ),
            None,
        )
        return response.json()

    def _fetch_worklogs(self, ids: list) -> list[dict]:
        if not ids:
            return []
        response = self._request(
            self.build_prepared_request(
                method="POST",
                url=f"{self.url_base}/rest/api/2/worklog/list",
                headers={**self.http_headers, "Content-Type": "application/json"},
                json={"ids": ids},
            ),
            None,
        )
        return response.json()

    @override
    def get_records(self, context: dict | None) -> Iterable[dict]:
        last_updated = self.get_starting_timestamp(context) or utils.strptime_to_utc(
            self.config["start_date"]
        )
        while True:
            ids_page = self._fetch_ids(last_updated)
            values = ids_page.get("values") or []
            if not values:
                break
            ids = [x["worklogId"] for x in values]
            worklogs = self._fetch_worklogs(ids)
            if not worklogs:
                break

            raise_if_bookmark_cannot_advance(worklogs)
            new_last_updated = max(utils.strptime_to_utc(w["updated"]) for w in worklogs)

            yield from worklogs

            # `since` has <= semantics, so a bookmark that does not move forward
            # re-requests an identical page forever. Reachable when /worklog/list
            # returns fewer records than the id page (deleted worklogs are omitted)
            # and they all share one `updated` value, which stays below the
            # 1000-record threshold raise_if_bookmark_cannot_advance guards.
            if new_last_updated <= last_updated:
                self.logger.warning(
                    f"Worklogs bookmark did not advance past {last_updated}; "
                    "stopping to avoid re-requesting the same page."
                )
                break

            last_updated = new_last_updated
            if ids_page.get("lastPage"):
                break
