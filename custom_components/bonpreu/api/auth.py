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


def is_mobile_callback_url(callback_url: str, expected_redirect_uri: str = REDIRECT_URI) -> bool:
    """Check if callback URL targets the expected Bonpreu mobile redirect URI."""
    parsed_callback = urlparse(callback_url)
    expected = urlparse(expected_redirect_uri)

    if parsed_callback.scheme != expected.scheme:
        return False
    if parsed_callback.netloc != expected.netloc:
        return False

    callback_path = parsed_callback.path or ""
    expected_path = expected.path or ""
    if callback_path not in {expected_path, f"{expected_path}/"}:
        return False

    return True


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
    if not is_mobile_callback_url(callback_url, expected_redirect_uri=expected_redirect_uri):
        raise BonpreuConfigError("Unexpected callback URI.")

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
    if secrets.compare_digest(received_state, expected_state):
        return True

    parsed_state = _parse_wrapped_mobile_state(received_state)
    if parsed_state is None:
        return False

    wrapped_redirect_uri, wrapped_state = parsed_state
    if not secrets.compare_digest(wrapped_redirect_uri, expected_redirect_uri):
        return False

    return secrets.compare_digest(wrapped_state, expected_state)


def _read_single_query_parameter(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    if not values:
        return None
    if len(values) != 1:
        raise BonpreuConfigError(f"Callback URL has duplicated '{key}' parameter.")
    value = values[0].strip()
    return value or None


def _parse_wrapped_mobile_state(received_state: str) -> tuple[str, str] | None:
    if not received_state.startswith("mobile_"):
        return None

    chunks = received_state.split("_")
    if len(chunks) != 4:
        return None

    _, encoded_redirect_uri, encoded_state, encoded_uuid = chunks
    if not encoded_redirect_uri or not encoded_state or not encoded_uuid:
        return None

    wrapped_redirect_uri = _try_b64_decode(encoded_redirect_uri)
    wrapped_state = _try_b64_decode(encoded_state)
    wrapped_uuid = _try_b64_decode(encoded_uuid)
    if not wrapped_redirect_uri or not wrapped_state or not wrapped_uuid:
        return None

    try:
        uuid.UUID(wrapped_uuid)
    except ValueError:
        return None

    return wrapped_redirect_uri, wrapped_state


def _try_b64_decode(value: str) -> str | None:
    padding = "=" * ((4 - len(value) % 4) % 4)
    candidate = value + padding

    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            decoded = decoder(candidate.encode("utf-8"))
            return decoded.decode("utf-8")
        except Exception:
            continue
    return None
