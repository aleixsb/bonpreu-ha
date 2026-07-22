"""Auth helpers for Bonpreu API."""

from __future__ import annotations

import base64
import secrets
import uuid
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse, urlunparse

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
    query = parse_query_preserving_plus(parsed.query)
    raw_query = parse_query_raw(parsed.query)

    code = _read_single_query_parameter(query, "code")
    raw_code = _read_single_query_parameter(raw_query, "code")
    state = _read_single_query_parameter(query, "state")
    oauth_error = _read_single_query_parameter(query, "error")
    error_description = _read_single_query_parameter(query, "error_description")

    if not state:
        raise BonpreuConfigError("Callback URL does not include query parameter 'state'.")

    if oauth_error:
        return CallbackParams(
            code=None,
            raw_code=raw_code,
            state=state,
            error=oauth_error,
            error_description=error_description,
        )

    if not code:
        raise BonpreuConfigError("Callback URL does not include query parameter 'code'.")

    return CallbackParams(code=code, raw_code=raw_code, state=state)


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


def infer_redirect_candidates_from_state(
    *,
    expected_state: str,
    received_state: str,
    default_redirect_uri: str,
) -> list[str]:
    """Infer token-exchange redirect URI candidates from wrapped mobile state."""
    candidates: list[str] = [default_redirect_uri]

    if not received_state.startswith("mobile_"):
        return candidates

    try:
        middle, wrapped_uuid = received_state[len("mobile_") :].rsplit("_", 1)
    except ValueError:
        return candidates

    try:
        uuid.UUID(wrapped_uuid)
    except ValueError:
        return candidates

    matched_encoded_redirect: str | None = None
    for encoded_state in _base64_variants(expected_state):
        suffix = f"_{encoded_state}"
        if middle.endswith(suffix):
            matched_encoded_redirect = middle[: -len(suffix)]
            break

    if not matched_encoded_redirect:
        return candidates

    for decoded in _decode_base64_text_variants(matched_encoded_redirect):
        parsed = urlparse(decoded)
        if not parsed.scheme:
            continue
        if decoded not in candidates:
            candidates.append(decoded)

    return candidates


def callback_redirect_uri_candidate(callback_url: str) -> str | None:
    """Return callback base URI for exchange when callback uses intermediary web endpoint."""
    parsed = urlparse(callback_url)
    if parsed.scheme == "https" and parsed.hostname == _INTERMEDIATE_HOST and parsed.path in _INTERMEDIATE_PATHS:
        return urlunparse(parsed._replace(query="", fragment=""))
    return None


def expand_redirect_candidate_variants(candidates: list[str]) -> list[str]:
    """Expand redirect URI candidates with small path/scheme variants."""
    expanded: list[str] = []

    def _add(candidate: str) -> None:
        if candidate and candidate not in expanded:
            expanded.append(candidate)

    for candidate in candidates:
        _add(candidate)
        parsed = urlparse(candidate)

        if parsed.path.endswith("/"):
            _add(urlunparse(parsed._replace(path=parsed.path.rstrip("/"))))

        if parsed.scheme == "bonpreu-atm" and parsed.netloc == "login" and parsed.path in {"", "/"}:
            _add("bonpreu-atm://login")

        if parsed.scheme == "https" and parsed.hostname == _INTERMEDIATE_HOST and parsed.path == "/sso-login":
            _add("https://www.compraonline.bonpreuesclat.cat/sso-login/auth")

        if parsed.scheme == "https" and parsed.hostname == _INTERMEDIATE_HOST and parsed.path == "/sso-login/auth":
            _add("https://www.compraonline.bonpreuesclat.cat/sso-login")

    return expanded


def parse_query_preserving_plus(query_string: str) -> dict[str, list[str]]:
    """Parse query string without translating '+' into spaces."""
    parsed: dict[str, list[str]] = {}
    if not query_string:
        return parsed

    for segment in query_string.split("&"):
        if not segment:
            continue
        key, sep, value = segment.partition("=")
        if not sep:
            key = segment
            value = ""

        decoded_key = unquote(key)
        decoded_value = unquote(value)
        parsed.setdefault(decoded_key, []).append(decoded_value)

    return parsed


def parse_query_raw(query_string: str) -> dict[str, list[str]]:
    """Parse query string while keeping values exactly as received."""
    parsed: dict[str, list[str]] = {}
    if not query_string:
        return parsed

    for segment in query_string.split("&"):
        if not segment:
            continue
        key, sep, value = segment.partition("=")
        if not sep:
            key = segment
            value = ""

        decoded_key = unquote(key)
        parsed.setdefault(decoded_key, []).append(value)

    return parsed


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


def _decode_base64_text_variants(value: str) -> list[str]:
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    decoded_values: list[str] = []

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(padded.encode("utf-8")).decode("utf-8")
        except Exception:
            continue
        if decoded not in decoded_values:
            decoded_values.append(decoded)

    return decoded_values


def _constant_time_equals(left: str, right: str) -> bool:
    return secrets.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
