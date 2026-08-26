"""Jira Authentication."""

from __future__ import annotations

from hotglue_singer_sdk.authenticators import OAuthAuthenticator, SingletonMeta
from typing_extensions import override

TOKEN_ENDPOINT = "https://auth.atlassian.com/oauth/token"


class JiraAuthenticator(OAuthAuthenticator, metaclass=SingletonMeta):
    """Authenticator class for Jira."""

    @override
    @property
    def oauth_request_body(self) -> dict:
        """Define the OAuth request body for the Jira API."""
        return {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": self.config["refresh_token"],
        }
