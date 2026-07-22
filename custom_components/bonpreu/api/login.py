"""Credential-based mobile OAuth login helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
import re
import time
from typing import Any
from urllib.parse import unquote, urljoin, urlparse

import aiohttp

from .auth import parse_query_preserving_plus
from .exceptions import (
    BonpreuInvalidCredentialsError,
    BonpreuInvalidEmailCodeError,
    BonpreuLoginChallengeError,
    BonpreuLoginExpiredError,
    BonpreuLoginFormError,
)

_ALLOWED_HTTPS_HOSTS = frozenset({"app.bonpreu.cat", "www.compraonline.bonpreuesclat.cat"})
_INTERMEDIATE_HOST = "www.compraonline.bonpreuesclat.cat"
_INTERMEDIATE_PATHS = frozenset({"/sso-login", "/sso-login/auth"})
_MOBILE_CALLBACK_SCHEME = "bonpreu-atm"
_MOBILE_CALLBACK_PATH = "/login"

_MAX_FLOW_STEPS = 20
_MAX_HTML_BYTES = 600_000
_FLOW_TTL_SECONDS = 600

_DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)


@dataclass(slots=True)
class ParsedHTMLForm:
    """Parsed HTML form data and fields."""

    method: str
    action_url: str
    fields: dict[str, str]
    field_types: dict[str, str]


@dataclass(slots=True)
class CredentialForm:
    """Credential form with discovered username/password field names."""

    form: ParsedHTMLForm
    username_field: str
    password_field: str


@dataclass(slots=True)
class EmailCodeForm:
    """Email-code verification form."""

    form: ParsedHTMLForm
    code_field: str


@dataclass(slots=True)
class LoginProgress:
    """Result of one login transaction step."""

    callback_url: str | None = None
    email_code_required: bool = False
    observed_redirect_uris: list[str] = field(default_factory=list)


@dataclass(slots=True)
class _PendingEmailCodeSubmission:
    form: ParsedHTMLForm
    code_field: str


class _FormParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._base_url = base_url
        self._forms: list[ParsedHTMLForm] = []
        self._current_method: str | None = None
        self._current_action: str | None = None
        self._current_fields: dict[str, str] | None = None
        self._current_types: dict[str, str] | None = None

    @property
    def forms(self) -> list[ParsedHTMLForm]:
        return self._forms

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        normalized = {key.lower(): (value or "") for key, value in attrs}

        if tag == "form":
            method = normalized.get("method", "post").strip().upper() or "POST"
            action = normalized.get("action", "")
            action_url = urljoin(self._base_url, action)
            self._current_method = method
            self._current_action = action_url
            self._current_fields = {}
            self._current_types = {}
            return

        if self._current_fields is None or self._current_types is None:
            return

        if tag == "input":
            self._capture_named_control(normalized)
            return

        if tag == "button":
            self._capture_named_control(normalized, fallback_type="button")

    def handle_endtag(self, tag: str) -> None:
        if tag != "form" or self._current_fields is None or self._current_types is None:
            return

        self._forms.append(
            ParsedHTMLForm(
                method=self._current_method or "POST",
                action_url=self._current_action or self._base_url,
                fields=dict(self._current_fields),
                field_types=dict(self._current_types),
            )
        )
        self._current_method = None
        self._current_action = None
        self._current_fields = None
        self._current_types = None

    def _capture_named_control(self, attrs: dict[str, str], *, fallback_type: str = "text") -> None:
        if self._current_fields is None or self._current_types is None:
            return

        name = attrs.get("name", "").strip()
        if not name:
            return
        if "disabled" in attrs:
            return

        if name not in self._current_fields:
            self._current_fields[name] = attrs.get("value", "")
            self._current_types[name] = attrs.get("type", fallback_type).strip().lower() or fallback_type


def parse_html_forms(html: str, *, base_url: str) -> list[ParsedHTMLForm]:
    """Parse HTML and return all forms with captured fields."""
    parser = _FormParser(base_url)
    parser.feed(html)
    parser.close()
    return parser.forms


def select_credentials_form(forms: list[ParsedHTMLForm]) -> CredentialForm | None:
    """Return the first form that looks like username/password sign-in."""
    for form in forms:
        password_field = _find_field(form, keywords=("password", "pass"), allowed_types={"password"})
        if not password_field:
            continue

        username_field = _find_field(
            form,
            keywords=("email", "username", "user", "login", "identifier"),
            allowed_types={"email", "text"},
        )
        if not username_field:
            username_field = _first_visible_text_field(form, exclude={password_field})
        if not username_field:
            continue

        return CredentialForm(
            form=form,
            username_field=username_field,
            password_field=password_field,
        )
    return None


def select_email_code_form(forms: list[ParsedHTMLForm]) -> EmailCodeForm | None:
    """Return form that looks like OTP/email verification input."""
    for form in forms:
        if any(ftype == "password" for ftype in form.field_types.values()):
            continue

        code_field = _find_field(
            form,
            keywords=("verification", "otp", "code", "token", "pin"),
            allowed_types={"text", "email", "tel", "number"},
        )
        if not code_field:
            code_field = _first_visible_text_field(form)
        if not code_field:
            continue

        return EmailCodeForm(form=form, code_field=code_field)
    return None


def extract_callback_url_from_location(current_url: str, location: str) -> str | None:
    """Resolve redirect location and return callback URL when oauth params are present."""
    resolved = urljoin(current_url, location)
    return extract_callback_url(resolved)


def extract_callback_url(candidate_url: str) -> str | None:
    """Return callback URL if candidate is supported callback with state/code or state/error."""
    parsed = urlparse(candidate_url)
    query = parse_query_preserving_plus(parsed.query)
    state = _read_query_value(query, "state")
    code = _read_query_value(query, "code")
    oauth_error = _read_query_value(query, "error")

    if not state or (not code and not oauth_error):
        return None

    is_mobile_callback = parsed.scheme == _MOBILE_CALLBACK_SCHEME and (
        parsed.path == _MOBILE_CALLBACK_PATH
        or (parsed.netloc == "login" and parsed.path in {"", "/"})
    )
    if is_mobile_callback:
        return candidate_url

    if parsed.scheme == "https" and parsed.hostname == _INTERMEDIATE_HOST and parsed.path in _INTERMEDIATE_PATHS:
        return candidate_url

    return None


class BonpreuCredentialLoginTransaction:
    """Stateful credential login transaction supporting OTP continuation."""

    def __init__(self, *, username: str, password: str, language: str = "ca-ES") -> None:
        self._username = username
        self._password = password
        self._language = language
        self._created_at = time.monotonic()
        self._closed = False
        self._pending_email_code: _PendingEmailCodeSubmission | None = None
        self._observed_redirect_uris: list[str] = []
        self._session = aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(unsafe=False),
            timeout=aiohttp.ClientTimeout(total=25),
            headers={
                "User-Agent": _DEFAULT_USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": self._language,
            },
        )

    async def async_start(self, authorization_url: str) -> LoginProgress:
        """Start credential login from OAuth authorization URL."""
        self._assert_active()
        self._pending_email_code = None
        self._observed_redirect_uris = []
        return await self._run_credential_phase(start_url=authorization_url)

    async def async_submit_email_code(self, email_code: str) -> LoginProgress:
        """Continue login by submitting the email verification code."""
        self._assert_active()
        pending = self._pending_email_code
        if pending is None:
            raise BonpreuLoginFormError("Email-code step is not pending.")

        code = email_code.strip()
        if not code:
            raise BonpreuInvalidEmailCodeError("Email verification code is empty.")

        self._pending_email_code = None
        payload = dict(pending.form.fields)
        payload[pending.code_field] = code
        return await self._run_email_code_phase(
            method=pending.form.method,
            url=pending.form.action_url,
            payload=payload,
        )

    async def async_close(self) -> None:
        """Close underlying HTTP resources."""
        if self._closed:
            return
        self._closed = True
        self._pending_email_code = None
        await self._session.close()

    async def _run_credential_phase(self, *, start_url: str) -> LoginProgress:
        method = "GET"
        url = start_url
        payload: dict[str, str] | None = None
        submitted_credentials = False
        attempted_intermediate_auth: set[str] = set()

        for _ in range(_MAX_FLOW_STEPS):
            self._assert_active()
            response_url, location, html = await self._send_request(
                method=method,
                url=url,
                payload=payload,
            )
            _collect_redirect_uri_candidates(response_url, self._observed_redirect_uris)

            callback_url = extract_callback_url(response_url)
            if callback_url:
                return self._build_progress(callback_url=callback_url)

            if location:
                resolved_redirect = urljoin(response_url, location)
                _collect_redirect_uri_candidates(resolved_redirect, self._observed_redirect_uris)
                callback_url = extract_callback_url_from_location(response_url, location)
                if callback_url:
                    if is_intermediate_callback_url(callback_url):
                        method = "GET"
                        url = callback_url
                        payload = None
                        continue
                    return self._build_progress(callback_url=callback_url)

                method = "GET"
                url = self._resolve_allowed_https_url(response_url, location)
                payload = None
                continue

            self._raise_for_browser_challenge(html, response_url)

            promoted_intermediate = promote_intermediate_callback_url(response_url)
            if promoted_intermediate and promoted_intermediate not in attempted_intermediate_auth:
                attempted_intermediate_auth.add(promoted_intermediate)
                method = "GET"
                url = promoted_intermediate
                payload = None
                continue

            callback_url = extract_mobile_callback_url_from_html(html)
            if callback_url:
                return self._build_progress(callback_url=callback_url)

            if is_intermediate_callback_url(response_url):
                return self._build_progress(callback_url=response_url)

            forms = parse_html_forms(html, base_url=response_url)

            if not submitted_credentials:
                credential_form = select_credentials_form(forms)
                if credential_form is not None:
                    method = credential_form.form.method
                    url = credential_form.form.action_url
                    payload = dict(credential_form.form.fields)
                    payload[credential_form.username_field] = self._username
                    payload[credential_form.password_field] = self._password
                    submitted_credentials = True
                    continue

            email_code_form = select_email_code_form(forms)
            if email_code_form is not None:
                self._pending_email_code = _PendingEmailCodeSubmission(
                    form=email_code_form.form,
                    code_field=email_code_form.code_field,
                )
                return self._build_progress(email_code_required=True)

            if submitted_credentials and select_credentials_form(forms) is not None:
                raise BonpreuInvalidCredentialsError("Bonpreu rejected username or password.")

            raise BonpreuLoginFormError("Could not find expected login form in Bonpreu response.")

        raise BonpreuLoginExpiredError("Credential login did not complete before timeout.")

    async def _run_email_code_phase(
        self,
        *,
        method: str,
        url: str,
        payload: dict[str, str],
    ) -> LoginProgress:
        current_method = method
        current_url = url
        current_payload: dict[str, str] | None = payload
        attempted_intermediate_auth: set[str] = set()

        for _ in range(_MAX_FLOW_STEPS):
            self._assert_active()
            response_url, location, html = await self._send_request(
                method=current_method,
                url=current_url,
                payload=current_payload,
            )
            _collect_redirect_uri_candidates(response_url, self._observed_redirect_uris)

            callback_url = extract_callback_url(response_url)
            if callback_url:
                return self._build_progress(callback_url=callback_url)

            if location:
                resolved_redirect = urljoin(response_url, location)
                _collect_redirect_uri_candidates(resolved_redirect, self._observed_redirect_uris)
                callback_url = extract_callback_url_from_location(response_url, location)
                if callback_url:
                    if is_intermediate_callback_url(callback_url):
                        current_method = "GET"
                        current_url = callback_url
                        current_payload = None
                        continue
                    return self._build_progress(callback_url=callback_url)

                current_method = "GET"
                current_url = self._resolve_allowed_https_url(response_url, location)
                current_payload = None
                continue

            self._raise_for_browser_challenge(html, response_url)

            promoted_intermediate = promote_intermediate_callback_url(response_url)
            if promoted_intermediate and promoted_intermediate not in attempted_intermediate_auth:
                attempted_intermediate_auth.add(promoted_intermediate)
                current_method = "GET"
                current_url = promoted_intermediate
                current_payload = None
                continue

            callback_url = extract_mobile_callback_url_from_html(html)
            if callback_url:
                return self._build_progress(callback_url=callback_url)

            if is_intermediate_callback_url(response_url):
                return self._build_progress(callback_url=response_url)

            forms = parse_html_forms(html, base_url=response_url)

            email_code_form = select_email_code_form(forms)
            if email_code_form is not None:
                self._pending_email_code = _PendingEmailCodeSubmission(
                    form=email_code_form.form,
                    code_field=email_code_form.code_field,
                )
                raise BonpreuInvalidEmailCodeError("Bonpreu rejected email verification code.")

            if select_credentials_form(forms) is not None:
                raise BonpreuInvalidCredentialsError("Bonpreu credentials were rejected during verification.")

            raise BonpreuLoginFormError("Could not finish Bonpreu verification flow.")

        raise BonpreuLoginExpiredError("Email-code verification did not complete before timeout.")

    def _build_progress(
        self,
        *,
        callback_url: str | None = None,
        email_code_required: bool = False,
    ) -> LoginProgress:
        return LoginProgress(
            callback_url=callback_url,
            email_code_required=email_code_required,
            observed_redirect_uris=list(self._observed_redirect_uris),
        )

    async def _send_request(
        self,
        *,
        method: str,
        url: str,
        payload: dict[str, str] | None,
    ) -> tuple[str, str | None, str]:
        request_url = self._ensure_allowed_request_url(url)
        kwargs: dict[str, Any] = {"allow_redirects": False}
        if method.upper() == "POST":
            kwargs["data"] = payload or {}

        async with self._session.request(method.upper(), request_url, **kwargs) as response:
            location = response.headers.get("Location")
            response_url = str(response.url)
            body = await response.content.read(_MAX_HTML_BYTES + 1)
            if len(body) > _MAX_HTML_BYTES:
                raise BonpreuLoginChallengeError("Bonpreu response is too large for scripted login.")
            html = body.decode(response.charset or "utf-8", errors="replace")
            return response_url, location, html

    def _ensure_allowed_request_url(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_HTTPS_HOSTS:
            raise BonpreuLoginChallengeError("Credential login refused non-Bonpreu redirect target.")
        return url

    def _resolve_allowed_https_url(self, current_url: str, location: str) -> str:
        resolved = urljoin(current_url, location)
        parsed = urlparse(resolved)
        if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_HTTPS_HOSTS:
            raise BonpreuLoginChallengeError("Credential login encountered unsupported redirect target.")
        return resolved

    def _assert_active(self) -> None:
        if self._closed:
            raise BonpreuLoginExpiredError("Credential login transaction is closed.")
        if (time.monotonic() - self._created_at) > _FLOW_TTL_SECONDS:
            raise BonpreuLoginExpiredError("Credential login transaction expired.")

    def _raise_for_browser_challenge(self, html: str, response_url: str) -> None:
        lowered = html.lower()
        challenge_markers = (
            "captcha",
            "cf-challenge",
            "recaptcha",
            "bot challenge",
            "access denied",
            "awswaf",
        )
        if any(marker in lowered for marker in challenge_markers):
            raise BonpreuLoginChallengeError(
                f"Bonpreu requires browser challenge on {urlparse(response_url).hostname}."
            )


def _find_field(
    form: ParsedHTMLForm,
    *,
    keywords: tuple[str, ...],
    allowed_types: set[str],
) -> str | None:
    for name, field_type in form.field_types.items():
        lowered_name = name.lower()
        if field_type not in allowed_types:
            continue
        if any(keyword in lowered_name for keyword in keywords):
            return name
    return None


def _first_visible_text_field(form: ParsedHTMLForm, *, exclude: set[str] | None = None) -> str | None:
    excluded = exclude or set()
    allowed_types = {"text", "email", "tel", "number"}
    for name, field_type in form.field_types.items():
        if name in excluded:
            continue
        if field_type in allowed_types:
            return name
    return None


def _read_query_value(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    if not values:
        return None
    if len(values) != 1:
        return None
    value = values[0].strip()
    return value or None


def is_intermediate_callback_url(candidate_url: str) -> bool:
    """Check whether URL is Bonpreu web intermediary callback endpoint."""
    parsed = urlparse(candidate_url)
    return (
        parsed.scheme == "https"
        and parsed.hostname == _INTERMEDIATE_HOST
        and parsed.path in _INTERMEDIATE_PATHS
    )


def promote_intermediate_callback_url(candidate_url: str) -> str | None:
    """Promote /sso-login callback URL to /sso-login/auth preserving query."""
    parsed = urlparse(candidate_url)
    if parsed.scheme != "https" or parsed.hostname != _INTERMEDIATE_HOST:
        return None
    if parsed.path != "/sso-login":
        return None
    promoted = parsed._replace(path="/sso-login/auth")
    return promoted.geturl()


def extract_mobile_callback_url_from_html(html: str) -> str | None:
    """Extract mobile callback URL from HTML/script content when present."""
    patterns = (
        r"bonpreu-atm://login\?[^\"'\s<]+",
        r"bonpreu-atm:\\/\\/login\?[^\"'\s<]+",
        r"bonpreu-atm:\\u002F\\u002Flogin\?[^\"'\s<]+",
    )
    for pattern in patterns:
        match = re.search(pattern, html)
        if not match:
            continue
        candidate = match.group(0)
        candidate = candidate.replace("\\/", "/")
        candidate = candidate.replace("\\u002F", "/")
        callback = extract_callback_url(candidate)
        if callback and callback.startswith(f"{_MOBILE_CALLBACK_SCHEME}://"):
            return callback
    return None


def _collect_redirect_uri_candidates(url: str, sink: list[str]) -> None:
    parsed = urlparse(url)
    query = parse_query_preserving_plus(parsed.query)
    values = query.get("redirect_uri") or []
    for value in values:
        cleaned = value.strip()
        if not cleaned:
            continue
        candidate = unquote(cleaned)
        parsed_candidate = urlparse(candidate)
        if not parsed_candidate.scheme:
            continue
        if candidate not in sink:
            sink.append(candidate)
