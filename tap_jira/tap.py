"""Jira tap class."""

from __future__ import annotations

from typing import Any

from hotglue_singer_sdk import Stream, Tap
from hotglue_singer_sdk import typing as th  # JSON schema typing helpers
from hotglue_singer_sdk.authenticators import OAuthAuthenticator
from typing_extensions import override

from tap_jira.auth import TOKEN_ENDPOINT, JiraAuthenticator
from tap_jira.streams import (
    ChangelogsStream,
    ComponentsStream,
    IssueCommentsStream,
    IssuePrioritiesStream,
    IssuesStream,
    IssueTransitionsStream,
    IssueTypesStream,
    ProjectCategoriesStream,
    ProjectsStream,
    ProjectTypesStream,
    ResolutionsStream,
    RolesStream,
    StatusesStream,
    UsersStream,
    VersionsStream,
    WorklogsStream,
    validate_dependencies,
)

STREAM_TYPES = [
    ProjectsStream,
    VersionsStream,
    ComponentsStream,
    ProjectTypesStream,
    ProjectCategoriesStream,
    IssueTypesStream,
    ResolutionsStream,
    RolesStream,
    UsersStream,
    StatusesStream,
    IssuePrioritiesStream,
    IssuesStream,
    IssueCommentsStream,
    ChangelogsStream,
    IssueTransitionsStream,
    WorklogsStream,
]


class TapJira(Tap):
    """Singer tap for Jira."""

    name = "tap-jira"

    # TODO: Update this section with the actual config values you expect:
    config_jsonschema = th.PropertiesList(
        th.Property(
            "start_date",
            th.DateTimeType,
            description="The earliest record date to sync",
            default="2000-01-01T00:00:00Z",
        ),
        th.Property(
            "api_url",
            th.StringType,
            description="Base URL for the Jira API",
            default="https://api.atlassian.com",
        ),
        th.Property(
            "client_id",
            th.StringType,
            description="OAuth client ID. Its presence selects OAuth over Basic Auth.",
        ),
        th.Property(
            "client_secret",
            th.StringType,
            description="OAuth client secret for the Jira OAuth app",
        ),
        th.Property(
            "refresh_token",
            th.StringType,
            description="OAuth refresh token for the Jira OAuth app",
        ),
        th.Property(
            "access_token",
            th.StringType,
            description="OAuth access token, refreshed by the tap as needed",
        ),
        th.Property(
            "expires_in",
            th.IntegerType,
            description="Absolute epoch expiry of the access token, written back by the tap",
        ),
        th.Property(
            "site_name",
            th.StringType,
            description="OAuth: name of the Jira site to sync. Defaults to the first "
            "site the token can access.",
        ),
        th.Property(
            "cloud_id",
            th.StringType,
            description="OAuth: cloud id of the Jira site, skipping site lookup",
        ),
        th.Property(
            "username",
            th.StringType,
            description="Basic Auth username, used when no client_id is set",
        ),
        th.Property(
            "password",
            th.StringType,
            description="Basic Auth password or API token",
        ),
        th.Property(
            "base_url",
            th.StringType,
            description="Basic Auth: your Jira URL, e.g. https://mycompany.atlassian.net",
        ),
        th.Property(
            "user_agent",
            th.StringType,
            description="Value sent as the User-Agent header",
        ),
    ).to_dict()

    @override
    def run_sync(self, catalog: Any = None, state: Any = None) -> None:
        """Validate stream dependencies before syncing, as the pre-SDK tap did."""
        self.register_streams_from_catalog(catalog)
        validate_dependencies(self)
        super().run_sync(catalog=catalog, state=state)

    @override
    def discover_streams(self) -> list[Stream]:
        """Return a list of discovered streams."""
        return [stream_class(tap=self) for stream_class in STREAM_TYPES]

    @classmethod
    def access_token_support(
        cls,
        connector: Any = None,
    ) -> tuple[type[OAuthAuthenticator], str]:
        """Return the authenticator class and OAuth token endpoint."""
        return JiraAuthenticator, TOKEN_ENDPOINT


if __name__ == "__main__":
    TapJira.cli()
