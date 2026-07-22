"""Auth helpers for Bonpreu API."""

from __future__ import annotations

import base64
import secrets
import uuid
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

from ..const import REDIRECT_URI
from .exceptions import BonpreuConfigError
from .models import CallbackParams

_INTERMEDIATE_HOST = "www.compraonline.bonpreuesclat.cat"
_INTERMEDIATE_PATHS = frozenset({"/sso-login", "/sso-login/auth"})


def format_auth_header_value(token: str) -> str:
    """Format Authorization value like mobile app: token:<urlencoded-token>."""
    return f"token:{quote(token, safe='')}"


def append_query_parameter(url: str, key: str, value: str) -> str:
    """Append (or overwrite) query param in URL."""
    parts = urlparse(url)
    query = parse_qs(parts.query, keep_blank_values=True)
    query[key] = [value]
    return urlunparse(parts._replace(query=urlencode(query, doseq=True)))


def is_expected_callback_url(callback_url: str, expected_redirect_uri: str = REDIRECT_URI) -> bool:
    """Check whether callback URL matches expected redirect URI origin/path."""
    parsed_callback = urlparse(callback_url)
    expected = urlparse(expected_redirect_uri)

    if parsed_callback.scheme.lower() != expected.scheme.lower():
        return False

    callback_host = (parsed_callback.hostname or "").lower()
    expected_host = (expected.hostname or "").lower()
    if callback_host != expected_host:
        return False

    callback_port = parsed_callback.port
    expected_port = expected.port
    callback_default_port = 443 if parsed_callback.scheme.lower() == "https" else 80
    expected_default_port = 443 if expected.scheme.lower() == "https" else 80
    if (callback_port or callback_default_port) != (expected_port or expected_default_port):
        return False

    if (parsed_callback.username or parsed_callback.password) and not (expected.username or expected.password):
        return False

    callback_path = parsed_callback.path or ""
    expected_path = expected.path or ""
    if callback_path not in {expected_path, f"{expected_path}/"}:
        return False

    return True


def is_mobile_callback_url(callback_url: str, expected_redirect_uri: str = REDIRECT_URI) -> bool:
    """Backward-compatible mobile callback matcher."""
    return is_expected_callback_url(callback_url, expected_redirect_uri=expected_redirect_uri)


def is_intermediate_callback_url(callback_url: str) -> bool:
    """Check whether callback URL is the Bonpreu web SSO intermediary URL."""
    parsed = urlparse(callback_url)
    if parsed.scheme != "https":
        return False
    if parsed.hostname != _INTERMEDIATE_HOST:
        return False
    return parsed.path in _INTERMEDIATE_PATHS


def parse_callback_url(callback_url: str, expected_redirect_uri: str = REDIRECT_URI) -> CallbackParams:
    """Parse and validate OAuth callback URL.

    Accepts only the expected Bonpreu mobile callback URI.
    """
    if not is_expected_callback_url(callback_url, expected_redirect_uri=expected_redirect_uri):
        raise BonpreuConfigError("Unexpected callback URI.")

    return parse_callback_query(callback_url)


def parse_callback_query(callback_url: str) -> CallbackParams:
    """Parse callback query parameters without validating callback host."""
    parsed = urlparse(callback_url)
    query = parse_qs(parsed.query, keep_blank_values=True)

    code = _read_single_query_parameter(query, "code")
    state = _read_single_query_parameter(query, "state")
    oauth_error = _read_single_query_parameter(query, "error")
    error_description = _read_single_query_parameter(query, "error_description")

    if not state:
        raise BonpreuConfigError("Callback URL does not include query parameter 'state'.")

    if oauth_error:
        return CallbackParams(
            code=None,
            state=state,
            error=oauth_error,
            error_description=error_description,
        )

    if not code:
        raise BonpreuConfigError("Callback URL does not include query parameter 'code'.")

    return CallbackParams(code=code, state=state)


def states_match(expected_state: str, received_state: str, expected_redirect_uri: str = REDIRECT_URI) -> bool:
    """Match OAuth state including Bonpreu wrapped state formats.

    Bonpreu may return states like:
    ``mobile_<base64 redirect uri>_<base64 expected_state>_<uuid>``
    """
    if _constant_time_equals(received_state, expected_state):
        return True

    return _matches_wrapped_mobile_state(
        received_state,
        expected_redirect_uri=expected_redirect_uri,
        expected_state=expected_state,
    )


def _read_single_query_parameter(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    if not values:
        return None
    if len(values) != 1:
        raise BonpreuConfigError(f"Callback URL has duplicated '{key}' parameter.")
    value = values[0].strip()
    return value or None


def _matches_wrapped_mobile_state(
    received_state: str,
    *,
    expected_redirect_uri: str,
    expected_state: str,
) -> bool:
    if not received_state.startswith("mobile_"):
        return False

    try:
        wrapped_prefix, wrapped_uuid = received_state.rsplit("_", 1)
    except ValueError:
        return False

    try:
        uuid.UUID(wrapped_uuid)
    except ValueError:
        return False

    expected_prefixes: set[str] = set()
    for encoded_redirect_uri in _base64_variants(expected_redirect_uri):
        for encoded_state in _base64_variants(expected_state):
            expected_prefixes.add(f"mobile_{encoded_redirect_uri}_{encoded_state}")

    return any(_constant_time_equals(wrapped_prefix, prefix) for prefix in expected_prefixes)


def _base64_variants(value: str) -> set[str]:
    raw = value.encode("utf-8")
    standard = base64.b64encode(raw).decode("utf-8")
    urlsafe = base64.urlsafe_b64encode(raw).decode("utf-8")

    variants = {
        standard,
        urlsafe,
        standard.rstrip("="),
        urlsafe.rstrip("="),
    }
    return {variant for variant in variants if variant}


def _constant_time_equals(left: str, right: str) -> bool:
    return secrets.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
