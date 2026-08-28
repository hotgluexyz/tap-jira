"""HTTP API client, including the JiraStream base classes."""

from __future__ import annotations

import json
import re
import time
from functools import cached_property
from pathlib import Path
from typing import Any

import requests
import singer
from hotglue_etl_exceptions import InvalidCredentialsError
from hotglue_singer_sdk.authenticators import APIAuthenticatorBase, BasicAuthenticator
from hotglue_singer_sdk.streams import RESTStream
from typing_extensions import override

# Carried over from the pre-SDK tap whose project plan specified:
# > our past experience has shown that issuing queries no more than once every
# > 10ms can help avoid performance issues
TIME_BETWEEN_REQUESTS_SECONDS = 0.01

DEFAULT_API_URL = "https://api.atlassian.com"
ACCESSIBLE_RESOURCES_URL = "https://api.atlassian.com/oauth/token/accessible-resources"

SCHEMAS_DIR = Path(__file__).parent / "schemas"


def load_schema(name: str) -> dict:
    """Load a stream schema, inlining any internal ``$ref`` definitions."""
    schema = json.loads((SCHEMAS_DIR / f"{name}.json").read_text())
    refs = schema.pop("definitions", {})
    if refs:
        singer.resolve_schema_references(schema, refs)
    return schema


class JiraStream(RESTStream):
    """Base stream for endpoints that return a bare JSON list."""

    records_jsonpath = "$[*]"
    next_page_token_jsonpath = None

    #: Shared across streams so the throttle applies tap-wide, not per stream.
    _next_request_at: float = 0.0

    @property
    def is_cloud(self) -> bool:
        return bool(self.config.get("client_id"))

    @override
    @cached_property
    def authenticator(self) -> APIAuthenticatorBase:
        if not self.is_cloud:
            username = self.config.get("username")
            password = self.config.get("password")
            if not username or not password:
                raise InvalidCredentialsError(
                    "Config must provide either `client_id` (OAuth) or "
                    "`username` and `password` (Basic Auth)."
                )
            return BasicAuthenticator.create_for_stream(self, username=username, password=password)

        authenticator_cls, auth_endpoint = self._tap.access_token_support(self._tap)
        return authenticator_cls(
            self,
            auth_endpoint=auth_endpoint,
            config_file=self._tap.config_file,
        )

    @property
    def api_url(self) -> str:
        return self.config.get("api_url", DEFAULT_API_URL).rstrip("/")

    @property
    def cloud_id(self) -> str:
        cached = getattr(self._tap, "_cloud_id", None)
        if cached:
            return cached

        cloud_id = self.config.get("cloud_id")
        if not cloud_id:
            response = requests.get(
                ACCESSIBLE_RESOURCES_URL,
                headers={
                    **self.authenticator.auth_headers,
                    "Accept": "application/json",
                },
                timeout=60,
            )
            response.raise_for_status()
            resources = response.json()
            site_name = self.config.get("site_name")
            if site_name:
                cloud_id = next((r["id"] for r in resources if r.get("name") == site_name), None)
                if not cloud_id:
                    names = [r.get("name") for r in resources]
                    raise InvalidCredentialsError(
                        f"No accessible Jira site named '{site_name}'. Available: {names}"
                    )
            elif resources:
                cloud_id = resources[0]["id"]
                self.logger.info(
                    f"Using Jira site '{resources[0].get('name')}' ({cloud_id}). "
                    "Set `site_name` or `cloud_id` in config to pin a specific site."
                )
            else:
                raise InvalidCredentialsError("This token has no accessible Jira sites.")

        self._tap._cloud_id = cloud_id
        return cloud_id

    @override
    @property
    def url_base(self) -> str:
        """Return the API URL root for the authorized Jira site."""
        if not self.is_cloud:
            base_url = self.config.get("base_url")
            if not base_url:
                raise InvalidCredentialsError("`base_url` is required when using Basic Auth.")
            # defend against a base_url that does or does not provide https://
            return "https://" + re.sub(r"^https?://", "", base_url).rstrip("/")
        return f"{self.api_url}/ex/jira/{self.cloud_id}"

    @override
    @property
    def http_headers(self) -> dict:
        """Return the http headers needed.

        Returns:
            A dictionary of HTTP headers.
        """
        headers = {"Accept": "application/json"}
        if "user_agent" in self.config:
            headers["User-Agent"] = self.config["user_agent"]
        return headers

    @override
    def _request(
        self, prepared_request: requests.PreparedRequest, context: dict | None
    ) -> requests.Response:
        """Send a request, throttled to one every ``TIME_BETWEEN_REQUESTS_SECONDS``."""
        wait = JiraStream._next_request_at - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        try:
            return super()._request(prepared_request, context)
        finally:
            JiraStream._next_request_at = time.monotonic() + TIME_BETWEEN_REQUESTS_SECONDS

    @override
    def response_error_message(self, response: requests.Response) -> str:
        """Build an error message, preferring Jira's own error text."""
        default = super().response_error_message(response)
        try:
            messages = response.json().get("errorMessages") or []
        except ValueError:
            return default
        if not messages:
            return default
        return f"{default}. Jira says: {messages[0]}"


class JiraOffsetStream(JiraStream):
    """Base stream for ``startAt`` endpoints that return a bare JSON array.

    Unlike the ``values``-envelope endpoints there is no ``maxResults`` in the
    response to compare against, so the page size is sent explicitly and a short
    page ends the walk.
    """

    records_jsonpath = "$[*]"
    page_size = 50

    @override
    def get_next_page_token(
        self,
        response: requests.Response,
        previous_token: Any | None,
    ) -> Any | None:
        """Return the next ``startAt`` offset, or None when the last page is read.

        Args:
            response: A raw `requests.Response`_ object.
            previous_token: The previous ``startAt`` offset.

        Returns:
            The next ``startAt`` offset, or None.

        .. _requests.Response:
            https://requests.readthedocs.io/en/latest/api/#requests.Response
        """
        page = response.json()
        if not isinstance(page, list) or len(page) < self.page_size:
            return None
        return (previous_token or 0) + len(page)

    @override
    def get_url_params(
        self,
        context: dict | None,
        next_page_token: Any | None,
    ) -> dict[str, Any]:
        """Return a dictionary of values to be used in URL parameterization.

        Args:
            context: The stream context.
            next_page_token: The next ``startAt`` offset.

        Returns:
            A dictionary of URL query parameters.
        """
        return {"startAt": next_page_token or 0, "maxResults": self.page_size}


class JiraPagedStream(JiraStream):
    """Base stream for ``startAt``/``maxResults`` endpoints that nest records
    under a ``values`` key."""

    records_jsonpath = "$.values[*]"
    page_size = 50
    order_by: str | None = None

    @override
    def get_next_page_token(
        self,
        response: requests.Response,
        previous_token: Any | None,
    ) -> Any | None:
        """Return the next ``startAt`` offset, or None when the last page is read."""
        data = response.json()
        if data.get("isLast"):
            return None
        page = data.get("values", [])
        # Jira echoes the page size it actually applied, which can be lower than the
        # one requested; trust the response over self.page_size.
        max_results = data.get("maxResults") or self.page_size
        if not max_results or len(page) < max_results:
            return None
        return (previous_token or 0) + max_results

    @override
    def get_url_params(
        self,
        context: dict | None,
        next_page_token: Any | None,
    ) -> dict[str, Any]:
        """Return a dictionary of values to be used in URL parameterization."""
        params: dict[str, Any] = {
            "startAt": next_page_token or 0,
            "maxResults": self.page_size,
        }
        if self.order_by:
            params["orderBy"] = self.order_by
        return params
