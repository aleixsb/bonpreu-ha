"""Data models used by Bonpreu client."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class OAuthUris:
    """OAuth URI payload."""

    authentication_uri: str
    reauthentication_uri: str
    registration_uri: str
    state: str


@dataclass(slots=True)
class TokenPair:
    """Access and refresh token pair."""

    access_token: str
    refresh_token: str | None


@dataclass(slots=True)
class CallbackParams:
    """Parsed callback query params from redirect URI."""

    code: str | None
    state: str
    error: str | None = None
    error_description: str | None = None
