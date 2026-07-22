#!/usr/bin/env python3
"""Standalone Bonpreu mobile-auth probe for iterative login debugging.

This script is intentionally independent from Home Assistant runtime and uses only
Python's standard library. It captures a sanitized trace (no credentials/tokens)
to stabilize the login flow before porting logic into the HA integration.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request
import uuid


BASE_URL = "https://api.bpe.osp.tech/rocket-osp/"
REDIRECT_URI = "bonpreu-atm://login"
API_KEY = "su95KBXYOL67yMpPxwNH8Eu4iGLk4TT235I5P8S7"
BANNER_ID = "dcbcfd72-cf23-44a2-8e14-8a38edd645a3"

HEADER_ACCEPT = "application/json,*/*"
HEADER_SOURCE = "android"
HEADER_SOURCE_VERSION = "home-assistant"

ALLOWED_LOGIN_HOSTS = frozenset({"app.bonpreu.cat", "www.compraonline.bonpreuesclat.cat"})
INTERMEDIATE_HOST = "www.compraonline.bonpreuesclat.cat"
INTERMEDIATE_PATHS = frozenset({"/sso-login", "/sso-login/auth"})
MOBILE_SCHEME = "bonpreu-atm"

MAX_HTML_BYTES = 600_000
MAX_LOGIN_STEPS = 25
TRANSACTION_TTL_SECONDS = 600

CREDENTIALS_FILE_NAME = "credentials.json"


class ProbeError(Exception):
    """Base probe exception."""


class ApiError(ProbeError):
    """API request failed."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class LoginError(ProbeError):
    """Login flow failed."""


class InvalidCredentialsError(LoginError):
    """Username/password rejected."""


class InvalidEmailCodeError(LoginError):
    """Email verification code rejected."""


class ChallengeRequiredError(LoginError):
    """Browser-only challenge/captcha detected."""


class FormDetectionError(LoginError):
    """Expected form fields were not detected."""


class ExpiredTransactionError(LoginError):
    """Persisted login transaction expired."""


@dataclass(slots=True)
class FormControl:
    """One named form control."""

    name: str
    control_type: str
    value: str
    field_id: str
    autocomplete: str
    maxlength: str
    placeholder: str


@dataclass(slots=True)
class ParsedForm:
    """Parsed form with controls and default payload fields."""

    method: str
    action_url: str
    controls: list[FormControl]
    payload_fields: dict[str, str]


@dataclass(slots=True)
class CredentialFormSelection:
    """Selected credentials form and field names."""

    form: ParsedForm
    username_field: str
    password_field: str


@dataclass(slots=True)
class EmailCodeFormSelection:
    """Selected email-code form and field name."""

    form: ParsedForm
    code_field: str


@dataclass(slots=True)
class LoginStepResult:
    """Result from one login phase."""

    callback_url: str | None = None
    pending_code_form: EmailCodeFormSelection | None = None
    observed_redirect_uris: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CallbackParams:
    """Parsed OAuth callback parameters."""

    code: str | None
    raw_code: str | None
    state: str
    error: str | None
    error_description: str | None


@dataclass(slots=True)
class OAuthUris:
    """OAuth URI payload from mobile API."""

    authentication_uri: str
    reauthentication_uri: str
    registration_uri: str
    state: str


@dataclass(slots=True)
class TokenPair:
    """Access/refresh token pair."""

    access_token: str
    refresh_token: str | None


@dataclass(slots=True)
class ProbeCredentials:
    """Probe credentials loaded from local file."""

    username: str
    password: str


@dataclass(slots=True)
class TransactionMeta:
    """Persisted OTP-resumable login transaction metadata."""

    transaction_id: str
    created_at: float
    expires_at: float
    oauth_state: str
    redirect_uri: str
    device_id: str
    device_token: str
    pending_form: dict[str, Any]
    observed_redirect_uris: list[str]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent urllib from auto-following redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        del req, fp, code, msg, headers, newurl
        return None


class _FormParser(HTMLParser):
    """HTML form parser capturing named controls."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._base_url = base_url
        self.forms: list[ParsedForm] = []
        self._current_method: str | None = None
        self._current_action: str | None = None
        self._controls: list[FormControl] | None = None
        self._payload: dict[str, str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        normalized = {key.lower(): (value or "") for key, value in attrs}

        if tag == "form":
            self._current_method = (normalized.get("method") or "post").strip().upper() or "POST"
            self._current_action = urllib.parse.urljoin(self._base_url, normalized.get("action", ""))
            self._controls = []
            self._payload = {}
            return

        if self._controls is None or self._payload is None:
            return

        if tag in {"input", "button"}:
            self._capture_named_control(normalized, fallback_type="button" if tag == "button" else "text")

    def handle_endtag(self, tag: str) -> None:
        if tag != "form" or self._controls is None or self._payload is None:
            return

        self.forms.append(
            ParsedForm(
                method=self._current_method or "POST",
                action_url=self._current_action or self._base_url,
                controls=list(self._controls),
                payload_fields=dict(self._payload),
            )
        )
        self._current_method = None
        self._current_action = None
        self._controls = None
        self._payload = None

    def _capture_named_control(self, attrs: dict[str, str], *, fallback_type: str) -> None:
        assert self._controls is not None
        assert self._payload is not None

        name = attrs.get("name", "").strip()
        if not name or "disabled" in attrs:
            return

        control_type = (attrs.get("type") or fallback_type).strip().lower() or fallback_type
        control = FormControl(
            name=name,
            control_type=control_type,
            value=attrs.get("value", ""),
            field_id=attrs.get("id", ""),
            autocomplete=attrs.get("autocomplete", ""),
            maxlength=attrs.get("maxlength", ""),
            placeholder=attrs.get("placeholder", ""),
        )
        self._controls.append(control)

        if name not in self._payload:
            self._payload[name] = control.value


class TracePrinter:
    """Sanitized trace logger."""

    def __init__(self, *, verbose: bool = True) -> None:
        self._lines: list[str] = []
        self._step = 0
        self._verbose = verbose

    @property
    def lines(self) -> list[str]:
        return list(self._lines)

    def request(
        self,
        *,
        method: str,
        url: str,
        status: int,
        location: str | None,
        forms: list[ParsedForm],
        hints: list[str],
    ) -> None:
        self._step += 1
        parsed = urllib.parse.urlparse(url)
        line = f"[{self._step:02d}] {method.upper()} {parsed.hostname}{parsed.path or '/'}"
        self._emit(line)
        self._emit(f"     status={status}")

        if parsed.query:
            keys = sorted(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())
            self._emit(f"     query_keys={keys}")

        if location:
            resolved = urllib.parse.urljoin(url, location)
            location_parsed = urllib.parse.urlparse(resolved)
            self._emit(f"     redirect={location_parsed.hostname}{location_parsed.path or '/'}")
            if location_parsed.query:
                keys = sorted(urllib.parse.parse_qs(location_parsed.query, keep_blank_values=True).keys())
                self._emit(f"     redirect_query_keys={keys}")

        for index, form in enumerate(forms):
            action_parsed = urllib.parse.urlparse(form.action_url)
            self._emit(
                f"     form[{index}]={form.method.upper()} {action_parsed.hostname}{action_parsed.path or '/'}"
            )
            field_chunks = []
            for control in form.controls:
                chunk = f"{control.name}:{control.control_type}"
                extras = []
                if control.name in {"bp-recaptcha-required"}:
                    safe_value = control.value.strip().lower()
                    if safe_value in {"true", "false", "1", "0", "yes", "no"}:
                        extras.append(f"value={safe_value}")
                if control.autocomplete:
                    extras.append(f"autocomplete={control.autocomplete}")
                if control.maxlength:
                    extras.append(f"maxlength={control.maxlength}")
                if control.field_id:
                    extras.append(f"id={control.field_id}")
                if extras:
                    chunk = f"{chunk} ({', '.join(extras)})"
                field_chunks.append(chunk)
            self._emit(f"     fields={field_chunks}")

        if hints:
            self._emit(f"     hints={hints}")

    def info(self, message: str) -> None:
        self._emit(message)

    def _emit(self, line: str) -> None:
        self._lines.append(line)
        if self._verbose:
            print(line)


class MobileApiClient:
    """Minimal synchronous mobile API client for auth probing."""

    def __init__(self, *, language: str = "ca-ES") -> None:
        self._language = normalize_api_language(language)

    def ensure_device_token(self, device_id: str) -> str:
        token = None
        try:
            token = self.get_device_token(device_id)
        except ApiError as err:
            if err.status_code != 404:
                raise

        if token:
            return token

        self.register_device(device_id)

        for attempt in range(5):
            try:
                token = self.get_device_token(device_id)
            except ApiError as err:
                if err.status_code != 404:
                    raise
                token = None
            if token:
                return token
            time.sleep(0.4 * (attempt + 1))

        raise ApiError("Could not obtain device token.")

    def get_device_token(self, device_id: str) -> str | None:
        data = self._request_json(
            "GET",
            f"v1/mobileDevice/{device_id}",
            headers={"Authorization": ""},
        )
        token = str(data.get("token") or "").strip()
        return token or None

    def register_device(self, device_id: str, *, device_model: str = "Home Assistant") -> None:
        self._request_json(
            "PUT",
            f"v1/mobileDevice/{device_id}",
            headers={"Authorization": ""},
            form_body={"deviceModel": device_model},
        )

    def get_oauth_uris(self) -> OAuthUris:
        raise NotImplementedError("Use get_oauth_uris_with_device_token().")

    def get_oauth_uris_with_device_token(
        self,
        device_token: str,
        *,
        use_alternative_mobile: bool = False,
    ) -> OAuthUris:
        path = "v1/authorize/uris/alternative-mobile" if use_alternative_mobile else "v1/authorize/uris"
        data = self._request_json(
            "GET",
            path,
            headers={"Authorization": format_auth_header_value(device_token)},
        )
        return OAuthUris(
            authentication_uri=str(data["authenticationUri"]),
            reauthentication_uri=str(data["reauthenticationUri"]),
            registration_uri=str(data["registrationUri"]),
            state=str(data["state"]),
        )

    def exchange_authorization_code(self, code: str, *, device_token: str, redirect_uri: str) -> TokenPair:
        auth_candidates = [
            format_auth_header_value(device_token),
            f"token:{device_token}",
        ]
        data: dict[str, Any] | None = None
        last_error: ApiError | None = None
        for auth_header in auth_candidates:
            try:
                candidate = self._request_json(
                    "POST",
                    "v1/authorize",
                    headers={"Authorization": auth_header},
                    json_body={
                        "authorizationCode": code,
                        "redirectUri": redirect_uri,
                    },
                )
            except ApiError as err:
                last_error = err
                continue
            if isinstance(candidate, dict):
                data = candidate
                break

        if data is None:
            if last_error is not None:
                raise last_error
            raise ApiError("Token exchange failed without response payload.")

        access_token = str(data.get("token") or "").strip()
        if not access_token:
            raise ApiError("Token exchange did not return access token.")
        refresh = str(data.get("refreshToken") or "").strip() or None
        return TokenPair(access_token=access_token, refresh_token=refresh)

    def get_user_current(self, access_token: str) -> dict[str, Any]:
        data = self._request_json(
            "GET",
            "v1/user/current",
            headers={"Authorization": format_auth_header_value(access_token)},
        )
        if not isinstance(data, dict):
            raise ApiError("User profile endpoint returned invalid payload.")
        return data

    def refresh_access_token(self, *, device_token: str, refresh_token: str) -> TokenPair:
        data = self._request_json(
            "POST",
            "v1/authorize/refresh",
            headers={"Authorization": format_auth_header_value(device_token)},
            json_body={"refreshToken": refresh_token},
        )
        if not isinstance(data, dict):
            raise ApiError("Refresh endpoint returned invalid payload.")

        access_token = str(data.get("token") or "").strip()
        if not access_token:
            raise ApiError("Refresh endpoint did not return access token.")
        refreshed_token = str(data.get("refreshToken") or "").strip() or None
        return TokenPair(access_token=access_token, refresh_token=refreshed_token)

    def search_products(
        self,
        *,
        access_token: str,
        query: str,
        screen_size: str = "S",
        max_products_to_decorate: int = 100,
        max_page_size: int = 100,
        include_additional_page_info: bool = True,
        sort_option_id: str | None = None,
        encoded_filters: str | None = None,
        category_id: str | None = None,
        page_token: str | None = None,
    ) -> dict[str, Any]:
        query_parts: list[str] = [
            f"q={urllib.parse.quote(query, safe='')}",
            f"screenSize={urllib.parse.quote(screen_size, safe='')}",
            f"maxProductsToDecorate={max_products_to_decorate}",
            f"maxPageSize={max_page_size}",
            f"includeAdditionalPageInfo={'true' if include_additional_page_info else 'false'}",
        ]
        if sort_option_id:
            query_parts.append(f"sortOptionId={urllib.parse.quote(sort_option_id, safe='')}")
        if encoded_filters:
            query_parts.append(f"filters={encoded_filters}")
        if category_id:
            query_parts.append(f"categoryId={urllib.parse.quote(category_id, safe='')}")
        if page_token:
            query_parts.append(f"pageToken={urllib.parse.quote(page_token, safe='')}")

        path = "v4/products/search?" + "&".join(query_parts)
        data = self._request_json(
            "GET",
            path,
            headers={"Authorization": format_auth_header_value(access_token)},
        )
        if not isinstance(data, dict):
            raise ApiError("Search endpoint returned invalid payload.")
        return data

    def get_product_detail(self, *, access_token: str, retailer_product_id: str) -> dict[str, Any]:
        encoded_id = urllib.parse.quote(retailer_product_id, safe="")
        data = self._request_json(
            "GET",
            f"v2/products/{encoded_id}/bop",
            headers={"Authorization": format_auth_header_value(access_token)},
        )
        if not isinstance(data, dict):
            raise ApiError("Product detail endpoint returned invalid payload.")
        return data

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        form_body: dict[str, str] | None = None,
    ) -> Any:
        url = urllib.parse.urljoin(BASE_URL, path)
        request_headers = {
            "Accept": HEADER_ACCEPT,
            "x-api-key": API_KEY,
            "BannerId": BANNER_ID,
            "Accept-Language": self._language,
            "Ecom-Request-Source": HEADER_SOURCE,
            "Ecom-Request-Source-Version": HEADER_SOURCE_VERSION,
        }
        if headers:
            request_headers.update(headers)

        body: bytes | None = None
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        elif form_body is not None:
            body = urllib.parse.urlencode(form_body).encode("utf-8")
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"

        request = urllib.request.Request(url=url, data=body, headers=request_headers, method=method.upper())

        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                payload = response.read()
                if not payload:
                    return {}
                return json.loads(payload.decode("utf-8"))
        except urllib.error.HTTPError as err:
            body_text = ""
            try:
                body_text = err.read().decode("utf-8", errors="replace")
            except Exception:
                body_text = ""
            raise ApiError(
                _build_http_error_message(err.code, path, body_text),
                status_code=err.code,
            ) from err
        except urllib.error.URLError as err:
            raise ApiError(f"Request failed for {path}: {err.reason}") from err
        except json.JSONDecodeError as err:
            raise ApiError(f"Invalid JSON response for {path}.") from err


class LoginFlowRunner:
    """Runs browser-like login requests with manual redirect handling."""

    def __init__(self, *, cookie_jar: Any, trace: TracePrinter, language: str = "ca-ES") -> None:
        self._trace = trace
        self._opener = urllib.request.build_opener(_NoRedirectHandler(), urllib.request.HTTPCookieProcessor(cookie_jar))
        self._default_headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/126.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": normalize_api_language(language),
        }

    def run_start(self, *, authorization_url: str, username: str, password: str) -> LoginStepResult:
        return self._run_loop(
            method="GET",
            url=authorization_url,
            payload=None,
            username=username,
            password=password,
            allow_credential_submit=True,
        )

    def run_resume(self, *, pending: EmailCodeFormSelection, email_code: str) -> LoginStepResult:
        payload = dict(pending.form.payload_fields)
        payload[pending.code_field] = email_code.strip()
        return self._run_loop(
            method=pending.form.method,
            url=pending.form.action_url,
            payload=payload,
            username=None,
            password=None,
            allow_credential_submit=False,
        )

    def _run_loop(
        self,
        *,
        method: str,
        url: str,
        payload: dict[str, str] | None,
        username: str | None,
        password: str | None,
        allow_credential_submit: bool,
    ) -> LoginStepResult:
        credentials_submitted = not allow_credential_submit
        observed_redirect_uris: list[str] = []
        attempted_intermediate_auth: set[str] = set()

        for _ in range(MAX_LOGIN_STEPS):
            response = self._request(method=method, url=url, payload=payload)
            collect_redirect_uri_candidates(response.url, observed_redirect_uris)

            callback = extract_mobile_callback_url(response.url)
            if callback:
                return LoginStepResult(callback_url=callback, observed_redirect_uris=observed_redirect_uris)

            redirect_location = response.headers.get("Location")
            forms = parse_forms(response.body_text, base_url=response.url)
            hints = extract_html_hints(response.body_text)
            self._trace.request(
                method=method,
                url=response.url,
                status=response.status,
                location=redirect_location,
                forms=forms,
                hints=hints,
            )

            if redirect_location:
                resolved_redirect = urllib.parse.urljoin(response.url, redirect_location)
                collect_redirect_uri_candidates(resolved_redirect, observed_redirect_uris)
                callback = extract_mobile_callback_url_from_location(response.url, redirect_location)
                if callback:
                    return LoginStepResult(callback_url=callback, observed_redirect_uris=observed_redirect_uris)

                callback = extract_callback_url_from_location(response.url, redirect_location)
                if callback:
                    if is_intermediate_callback_url(callback):
                        method = "GET"
                        url = callback
                        payload = None
                        continue
                    return LoginStepResult(callback_url=callback, observed_redirect_uris=observed_redirect_uris)

                method = "GET"
                url = resolve_allowed_login_redirect(response.url, redirect_location)
                payload = None
                continue

            maybe_raise_challenge(response.status, response.body_text, response.url, forms=forms)

            promoted_intermediate = promote_intermediate_callback_url(response.url)
            if promoted_intermediate and promoted_intermediate not in attempted_intermediate_auth:
                attempted_intermediate_auth.add(promoted_intermediate)
                method = "GET"
                url = promoted_intermediate
                payload = None
                continue

            if is_intermediate_callback_url(response.url):
                return LoginStepResult(callback_url=response.url, observed_redirect_uris=observed_redirect_uris)

            callback = extract_mobile_callback_url_from_html(response.body_text)
            if callback:
                return LoginStepResult(callback_url=callback, observed_redirect_uris=observed_redirect_uris)

            if not credentials_submitted:
                selected = select_credentials_form(forms)
                if selected is not None:
                    if not username or not password:
                        raise FormDetectionError("Credential values were not provided.")
                    payload = dict(selected.form.payload_fields)
                    payload[selected.username_field] = username
                    payload[selected.password_field] = password
                    method = selected.form.method
                    url = selected.form.action_url
                    credentials_submitted = True
                    continue

            code_form = select_email_code_form(forms)
            if code_form is not None:
                if credentials_submitted:
                    return LoginStepResult(
                        pending_code_form=code_form,
                        observed_redirect_uris=observed_redirect_uris,
                    )

            if credentials_submitted and select_credentials_form(forms) is not None:
                if not allow_credential_submit:
                    raise ExpiredTransactionError(
                        "OTP transaction is no longer valid; start a new login attempt."
                    )
                retry_reason = classify_login_retry_reason(response.body_text, hints=hints)
                if retry_reason == "captcha":
                    raise ChallengeRequiredError("Credential submit requires captcha/browser challenge.")
                raise InvalidCredentialsError("Credential form reappeared after submission.")

            raise FormDetectionError("No expected login continuation form found.")

        raise ExpiredTransactionError("Login loop exhausted maximum redirect/form steps.")

    def _request(self, *, method: str, url: str, payload: dict[str, str] | None) -> "HttpResponse":
        ensure_allowed_login_request(url)

        headers = dict(self._default_headers)
        data_bytes: bytes | None = None
        if method.upper() == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            data_bytes = urllib.parse.urlencode(payload or {}).encode("utf-8")

        request = urllib.request.Request(url=url, headers=headers, data=data_bytes, method=method.upper())

        try:
            response = self._opener.open(request, timeout=25)
        except urllib.error.HTTPError as err:
            response = err

        status = int(response.getcode() or 0)
        response_url = response.geturl()
        body_bytes = response.read(MAX_HTML_BYTES + 1)
        if len(body_bytes) > MAX_HTML_BYTES:
            raise ChallengeRequiredError("Response body exceeded safety limit.")
        body_text = body_bytes.decode(response.headers.get_content_charset("utf-8"), errors="replace")
        headers_map = dict(response.headers.items())
        return HttpResponse(status=status, url=response_url, headers=headers_map, body_text=body_text)


@dataclass(slots=True)
class HttpResponse:
    """Simplified HTTP response representation."""

    status: int
    url: str
    headers: dict[str, str]
    body_text: str


def normalize_api_language(language: str | None) -> str:
    """Normalize language to known Bonpreu locales."""
    if not language:
        return "ca-ES"

    normalized = language.strip().replace("_", "-").lower()
    if normalized.startswith("ca"):
        return "ca-ES"
    if normalized.startswith("es"):
        return "es-ES"
    return "ca-ES"


def parse_forms(html: str, *, base_url: str) -> list[ParsedForm]:
    """Parse forms from HTML document."""
    parser = _FormParser(base_url)
    parser.feed(html)
    parser.close()
    return parser.forms


def select_credentials_form(forms: list[ParsedForm]) -> CredentialFormSelection | None:
    """Detect username/password form."""
    for form in forms:
        field_types = {control.name: control.control_type for control in form.controls}
        password_field = find_field(field_types, keywords=("password", "pass"), allowed={"password"})
        if not password_field:
            continue

        username_field = find_field(
            field_types,
            keywords=("email", "username", "user", "login", "identifier"),
            allowed={"email", "text"},
        )
        if not username_field:
            username_field = first_text_field(field_types, exclude={password_field})
        if not username_field:
            continue

        return CredentialFormSelection(
            form=form,
            username_field=username_field,
            password_field=password_field,
        )
    return None


def select_email_code_form(forms: list[ParsedForm]) -> EmailCodeFormSelection | None:
    """Detect email verification form."""
    for form in forms:
        field_types = {control.name: control.control_type for control in form.controls}
        if any(ftype == "password" for ftype in field_types.values()):
            continue

        code_field = find_field(
            field_types,
            keywords=("verification", "otp", "code", "token", "pin"),
            allowed={"text", "number", "tel", "email"},
        )
        if not code_field:
            candidates = [
                control
                for control in form.controls
                if control.control_type in {"text", "number", "tel", "email"}
            ]
            if len(candidates) == 1:
                code_field = candidates[0].name

        if code_field:
            return EmailCodeFormSelection(form=form, code_field=code_field)
    return None


def find_field(field_types: dict[str, str], *, keywords: tuple[str, ...], allowed: set[str]) -> str | None:
    """Find named field matching keyword and allowed type."""
    for name, field_type in field_types.items():
        if field_type not in allowed:
            continue
        lowered_name = name.lower()
        if any(keyword in lowered_name for keyword in keywords):
            return name
    return None


def first_text_field(field_types: dict[str, str], *, exclude: set[str] | None = None) -> str | None:
    """Find first visible text-like field."""
    excluded = exclude or set()
    for name, field_type in field_types.items():
        if name in excluded:
            continue
        if field_type in {"text", "email", "number", "tel"}:
            return name
    return None


def maybe_raise_challenge(
    status: int,
    html: str,
    response_url: str,
    *,
    forms: list[ParsedForm] | None = None,
) -> None:
    """Detect browser-only challenge responses."""
    lowered = html.lower()
    has_actionable_form = bool(forms and (select_credentials_form(forms) or select_email_code_form(forms)))

    strong_markers = (
        "cf-challenge",
        "just a moment",
        "awswaf",
        "access denied",
        "bot challenge",
        "captcha challenge",
        "verify you are human",
    )
    if status in {401, 403, 429} and any(marker in lowered for marker in strong_markers):
        raise ChallengeRequiredError(f"Browser challenge detected on {urllib.parse.urlparse(response_url).hostname}.")

    if has_actionable_form:
        return

    if any(marker in lowered for marker in strong_markers):
        raise ChallengeRequiredError(f"Browser challenge detected on {urllib.parse.urlparse(response_url).hostname}.")


def classify_login_retry_reason(html: str, *, hints: list[str] | None = None) -> str:
    """Classify why the login form reappeared after credential submit."""
    lowered = html.lower()
    joined_hints = " ".join((hints or [])).lower()
    captcha_markers = (
        "g-recaptcha-response",
        "verify you are human",
        "captcha",
        "recaptcha",
    )
    strong_challenge_markers = (
        "verify you are human",
        "cf-challenge",
        "just a moment",
        "access denied",
        "bot challenge",
        "captcha challenge",
        "awswaf",
    )
    invalid_credential_markers = (
        "invalid username or password",
        "invalid user credentials",
        "credenciales",
        "credencials",
        "contrasena incorrecta",
        "password incorrect",
        "usuari o contrasenya",
        "usuari i/o contrasenya",
        "usuari o contrasenya incorrectes",
    )

    if any(marker in joined_hints for marker in invalid_credential_markers):
        return "credentials"

    if any(marker in joined_hints for marker in captcha_markers):
        return "captcha"

    if any(marker in lowered for marker in invalid_credential_markers):
        return "credentials"

    if any(marker in lowered for marker in strong_challenge_markers):
        return "captcha"

    return "credentials"


def extract_html_hints(html: str) -> list[str]:
    """Extract short diagnostic text snippets without leaking secrets."""
    lowered = html.lower()
    if not any(keyword in lowered for keyword in ("invalid", "error", "captcha", "recaptcha", "incorrect", "wrong")):
        return []

    stripped = re.sub(r"<script[\s\S]*?</script>", " ", html, flags=re.IGNORECASE)
    stripped = re.sub(r"<style[\s\S]*?</style>", " ", stripped, flags=re.IGNORECASE)
    stripped = re.sub(r"<[^>]+>", "\n", stripped)

    hints: list[str] = []
    for raw_line in stripped.splitlines():
        line = " ".join(raw_line.strip().split())
        if not line:
            continue
        lower_line = line.lower()
        if "@" in line:
            continue
        if len(line) > 180:
            continue
        if any(keyword in lower_line for keyword in ("invalid", "error", "captcha", "recaptcha", "incorrect", "wrong")):
            hints.append(line)
        if len(hints) >= 5:
            break
    return hints


def ensure_allowed_login_request(url: str) -> None:
    """Allow only HTTPS requests to known Bonpreu login hosts."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_LOGIN_HOSTS:
        raise ChallengeRequiredError(f"Refusing login request to unsupported host: {parsed.hostname}")


def resolve_allowed_login_redirect(current_url: str, location: str) -> str:
    """Resolve redirect target and validate host allow-list."""
    resolved = urllib.parse.urljoin(current_url, location)
    parsed = urllib.parse.urlparse(resolved)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_LOGIN_HOSTS:
        raise ChallengeRequiredError(f"Unsupported redirect host: {parsed.hostname}")
    return resolved


def extract_callback_url_from_location(current_url: str, location: str) -> str | None:
    """Resolve redirect location and return callback URL when recognized."""
    resolved = urllib.parse.urljoin(current_url, location)
    return extract_callback_url(resolved)


def extract_mobile_callback_url_from_location(current_url: str, location: str) -> str | None:
    """Resolve redirect location and return only mobile callback URL when recognized."""
    resolved = urllib.parse.urljoin(current_url, location)
    return extract_mobile_callback_url(resolved)


def extract_callback_url(candidate_url: str) -> str | None:
    """Return callback URL when state+(code|error) are present on supported targets."""
    parsed = urllib.parse.urlparse(candidate_url)
    query = parse_query_preserving_plus(parsed.query)
    state = read_query_value(query, "state")
    code = read_query_value(query, "code")
    oauth_error = read_query_value(query, "error")

    if not state or (not code and not oauth_error):
        return None

    is_mobile = parsed.scheme == MOBILE_SCHEME and (
        parsed.path == "/login" or (parsed.netloc == "login" and parsed.path in {"", "/"})
    )
    if is_mobile:
        return candidate_url

    if parsed.scheme == "https" and parsed.hostname == INTERMEDIATE_HOST and parsed.path in INTERMEDIATE_PATHS:
        return candidate_url

    return None


def extract_mobile_callback_url(candidate_url: str) -> str | None:
    """Return callback URL only when target is the mobile URI with state+(code|error)."""
    parsed = urllib.parse.urlparse(candidate_url)
    query = parse_query_preserving_plus(parsed.query)
    state = read_query_value(query, "state")
    code = read_query_value(query, "code")
    oauth_error = read_query_value(query, "error")

    if not state or (not code and not oauth_error):
        return None

    is_mobile = parsed.scheme == MOBILE_SCHEME and (
        parsed.path == "/login" or (parsed.netloc == "login" and parsed.path in {"", "/"})
    )
    if is_mobile:
        return candidate_url
    return None


def is_intermediate_callback_url(candidate_url: str) -> bool:
    """Return True when URL is Bonpreu web intermediary callback endpoint."""
    parsed = urllib.parse.urlparse(candidate_url)
    return (
        parsed.scheme == "https"
        and parsed.hostname == INTERMEDIATE_HOST
        and parsed.path in INTERMEDIATE_PATHS
    )


def promote_intermediate_callback_url(candidate_url: str) -> str | None:
    """Promote /sso-login callback URL to /sso-login/auth preserving query."""
    parsed = urllib.parse.urlparse(candidate_url)
    if parsed.scheme != "https" or parsed.hostname != INTERMEDIATE_HOST:
        return None
    if parsed.path != "/sso-login":
        return None
    promoted = parsed._replace(path="/sso-login/auth")
    return urllib.parse.urlunparse(promoted)


def extract_mobile_callback_url_from_html(html: str) -> str | None:
    """Extract mobile callback URL from HTML/script content when present."""
    # Match direct and escaped variants used inside inline scripts.
    patterns = (
        r"bonpreu-atm://login\?[^\"'\s<]+",
        r"bonpreu-atm:\\/\\/login\?[^\"'\s<]+",
        r"bonpreu-atm:\u002F\u002Flogin\?[^\"'\s<]+",
    )
    for pattern in patterns:
        match = re.search(pattern, html)
        if not match:
            continue

        candidate = match.group(0)
        candidate = candidate.replace("\\/", "/")
        candidate = candidate.replace("\\u002F", "/")
        callback = extract_mobile_callback_url(candidate)
        if callback:
            return callback
    return None


def collect_redirect_uri_candidates(url: str, sink: list[str]) -> None:
    """Collect redirect_uri query parameter values from URL if present."""
    parsed = urllib.parse.urlparse(url)
    query = parse_query_preserving_plus(parsed.query)
    values = query.get("redirect_uri") or []
    for value in values:
        cleaned = value.strip()
        if not cleaned:
            continue
        candidate = urllib.parse.unquote(cleaned)
        parsed_candidate = urllib.parse.urlparse(candidate)
        if not parsed_candidate.scheme:
            continue
        if candidate not in sink:
            sink.append(candidate)


def parse_callback_params(callback_url: str) -> CallbackParams:
    """Parse callback parameters without exposing query values in logs."""
    parsed = urllib.parse.urlparse(callback_url)
    query = parse_query_preserving_plus(parsed.query)
    raw_query = parse_query_raw(parsed.query)
    state = read_query_value(query, "state")
    if not state:
        raise LoginError("Callback did not include state.")

    return CallbackParams(
        code=read_query_value(query, "code"),
        raw_code=read_query_value(raw_query, "code"),
        state=state,
        error=read_query_value(query, "error"),
        error_description=read_query_value(query, "error_description"),
    )


def read_query_value(query: dict[str, list[str]], key: str) -> str | None:
    """Read one query value when key appears exactly once."""
    values = query.get(key)
    if not values or len(values) != 1:
        return None
    value = values[0].strip()
    return value or None


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

        decoded_key = urllib.parse.unquote(key)
        decoded_value = urllib.parse.unquote(value)
        parsed.setdefault(decoded_key, []).append(decoded_value)

    return parsed


def parse_query_raw(query_string: str) -> dict[str, list[str]]:
    """Parse query string keeping values exactly as they appear (no decoding)."""
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
        decoded_key = urllib.parse.unquote(key)
        parsed.setdefault(decoded_key, []).append(value)
    return parsed


def states_match(expected_state: str, received_state: str, *, expected_redirect_uri: str) -> bool:
    """Match direct state or wrapped `mobile_<b64 redirect>_<b64 state>_<uuid>` states."""
    if secrets.compare_digest(received_state.encode("utf-8"), expected_state.encode("utf-8")):
        return True

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
    for encoded_redirect in base64_variants(expected_redirect_uri):
        for encoded_state in base64_variants(expected_state):
            expected_prefixes.add(f"mobile_{encoded_redirect}_{encoded_state}")

    return any(
        secrets.compare_digest(wrapped_prefix.encode("utf-8"), candidate.encode("utf-8"))
        for candidate in expected_prefixes
    )


def infer_redirect_candidates_from_state(
    *,
    expected_state: str,
    received_state: str,
    default_redirect_uri: str,
) -> list[str]:
    """Infer possible redirect URIs from wrapped mobile state when present."""
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
    for encoded_state in base64_variants(expected_state):
        suffix = f"_{encoded_state}"
        if middle.endswith(suffix):
            matched_encoded_redirect = middle[: -len(suffix)]
            break

    if not matched_encoded_redirect:
        return candidates

    for decoded in decode_base64_text_variants(matched_encoded_redirect):
        parsed = urllib.parse.urlparse(decoded)
        if not parsed.scheme:
            continue
        if decoded not in candidates:
            candidates.append(decoded)

    return candidates


def decode_base64_text_variants(value: str) -> list[str]:
    """Decode potentially padded/unpadded base64 text using std and urlsafe codecs."""
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    decoded_values: list[str] = []

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded.encode("utf-8"))
            text = raw.decode("utf-8")
        except Exception:
            continue
        if text not in decoded_values:
            decoded_values.append(text)

    return decoded_values


def base64_variants(value: str) -> set[str]:
    """Return standard/urlsafe base64 variants with and without padding."""
    raw = value.encode("utf-8")
    standard = base64.b64encode(raw).decode("utf-8")
    urlsafe = base64.urlsafe_b64encode(raw).decode("utf-8")
    variants = {standard, urlsafe, standard.rstrip("="), urlsafe.rstrip("=")}
    return {variant for variant in variants if variant}


def append_query_parameter(url: str, key: str, value: str) -> str:
    """Append (or override) one query parameter in URL."""
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    query[key] = [value]
    rebuilt = parsed._replace(query=urllib.parse.urlencode(query, doseq=True))
    return urllib.parse.urlunparse(rebuilt)


def format_auth_header_value(token: str) -> str:
    """Format Authorization header value used by mobile API."""
    return f"token:{urllib.parse.quote(token, safe='')}"


def probe_home_dir() -> Path:
    """Return probe data directory path."""
    env_path = os.getenv("BONPREU_PROBE_HOME")
    if env_path:
        return Path(env_path).expanduser()
    return Path.home() / ".bonpreu-auth-probe"


def ensure_private_dir(path: Path) -> None:
    """Create directory with restricted permissions."""
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def write_private_json(path: Path, data: dict[str, Any]) -> None:
    """Write JSON with restrictive file permissions."""
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.chmod(path, 0o600)


def read_json(path: Path) -> dict[str, Any]:
    """Read JSON file."""
    return json.loads(path.read_text(encoding="utf-8"))


def credentials_file_path(home: Path, *, override: str | None = None) -> Path:
    """Return credentials file path."""
    if override:
        return Path(override).expanduser()
    return home / CREDENTIALS_FILE_NAME


def load_credentials_file(home: Path, *, override: str | None = None) -> ProbeCredentials:
    """Load username/password from local credentials file."""
    path = credentials_file_path(home, override=override)
    if not path.exists():
        raise ProbeError(
            f"Credentials file not found at {path}. "
            "Create it with: credentials store --username <email> --password <password>"
        )

    raw = read_json(path)
    username = str(raw.get("username") or "").strip()
    password = str(raw.get("password") or "").strip()

    if not username or not password:
        raise ProbeError(f"Credentials file {path} must include non-empty username and password.")

    return ProbeCredentials(username=username, password=password)


def store_credentials_file(
    home: Path,
    *,
    username: str,
    password: str,
    override: str | None = None,
) -> Path:
    """Store credentials in a local chmod-600 JSON file."""
    if not username.strip() or not password.strip():
        raise ProbeError("Username and password are required.")

    path = credentials_file_path(home, override=override)
    ensure_private_dir(path.parent)
    write_private_json(
        path,
        {
            "username": username.strip(),
            "password": password.strip(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    return path


def transactions_dir(home: Path) -> Path:
    """Return transaction directory path."""
    return home / "transactions"


def clean_expired_transactions(home: Path, *, now: float | None = None) -> None:
    """Delete expired transaction directories."""
    tx_dir = transactions_dir(home)
    if not tx_dir.exists():
        return
    current = now if now is not None else time.time()

    for child in tx_dir.iterdir():
        if not child.is_dir():
            continue
        meta_path = child / "meta.json"
        if not meta_path.exists():
            shutil.rmtree(child, ignore_errors=True)
            continue
        try:
            meta = read_json(meta_path)
            expires_at = float(meta.get("expires_at") or 0)
        except Exception:
            shutil.rmtree(child, ignore_errors=True)
            continue
        if current >= expires_at:
            shutil.rmtree(child, ignore_errors=True)


def save_transaction(home: Path, meta: TransactionMeta, cookie_jar: Any, trace: TracePrinter) -> Path:
    """Persist OTP-resumable transaction metadata and cookies."""
    tx_dir = transactions_dir(home) / meta.transaction_id
    ensure_private_dir(transactions_dir(home))
    ensure_private_dir(tx_dir)

    write_private_json(tx_dir / "meta.json", asdict(meta))

    cookie_path = tx_dir / "cookies.txt"
    cookie_jar.save(str(cookie_path), ignore_discard=True, ignore_expires=True)
    os.chmod(cookie_path, 0o600)

    trace_path = tx_dir / "trace.log"
    trace_path.write_text("\n".join(trace.lines) + "\n", encoding="utf-8")
    os.chmod(trace_path, 0o600)

    return tx_dir


def load_transaction(home: Path, transaction_id: str) -> tuple[TransactionMeta, Any, list[str]]:
    """Load persisted transaction and cookie jar."""
    tx_dir = transactions_dir(home) / transaction_id
    meta_path = tx_dir / "meta.json"
    cookie_path = tx_dir / "cookies.txt"
    trace_path = tx_dir / "trace.log"

    if not meta_path.exists() or not cookie_path.exists():
        raise ProbeError(f"Transaction {transaction_id} not found.")

    raw = read_json(meta_path)
    meta = TransactionMeta(
        transaction_id=str(raw["transaction_id"]),
        created_at=float(raw["created_at"]),
        expires_at=float(raw["expires_at"]),
        oauth_state=str(raw["oauth_state"]),
        redirect_uri=str(raw["redirect_uri"]),
        device_id=str(raw["device_id"]),
        device_token=str(raw["device_token"]),
        pending_form=dict(raw["pending_form"]),
        observed_redirect_uris=[str(item) for item in raw.get("observed_redirect_uris", [])],
    )

    if time.time() >= meta.expires_at:
        raise ExpiredTransactionError("Transaction expired; start a new login.")

    cookie_jar = urllib.request.HTTPCookieProcessor().cookiejar
    # Replace generated cookie jar with MozillaCookieJar to load/save explicitly.
    cookie_jar = urllib.request.HTTPCookieProcessor().cookiejar
    # urllib's internal jar may not expose load/save; use MozillaCookieJar explicitly.
    import http.cookiejar

    moz = http.cookiejar.MozillaCookieJar(str(cookie_path))
    moz.load(ignore_discard=True, ignore_expires=True)

    previous_trace: list[str] = []
    if trace_path.exists():
        previous_trace = trace_path.read_text(encoding="utf-8").splitlines()

    return meta, moz, previous_trace


def delete_transaction(home: Path, transaction_id: str) -> None:
    """Delete one persisted transaction directory."""
    shutil.rmtree(transactions_dir(home) / transaction_id, ignore_errors=True)


def make_cookie_jar() -> Any:
    """Return in-memory MozillaCookieJar for save/load compatibility."""
    import http.cookiejar

    return http.cookiejar.MozillaCookieJar()


def _build_http_error_message(status: int, path: str, body: str) -> str:
    """Build concise API error message with safe reason extraction."""
    base = f"HTTP {status} for {path}"
    if not body:
        return base
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return base

    if isinstance(parsed, dict):
        for key in ("reason", "error", "code", "message"):
            value = parsed.get(key)
            if isinstance(value, str) and value.strip():
                return f"{base}: {value.strip()}"
    return base


def run_start(
    *,
    home: Path,
    language: str = "ca-ES",
    credentials_file: str | None = None,
    use_alternative_mobile: bool = False,
) -> int:
    """Start credential flow until callback success or OTP prompt."""
    clean_expired_transactions(home)
    credentials = load_credentials_file(home, override=credentials_file)

    trace = TracePrinter(verbose=True)
    api = MobileApiClient(language=language)
    device_id = str(uuid.uuid4())

    trace.info("Starting mobile API device bootstrap.")
    device_token = api.ensure_device_token(device_id)
    trace.info("Device token resolved (value hidden).")

    uris = api.get_oauth_uris_with_device_token(
        device_token,
        use_alternative_mobile=use_alternative_mobile,
    )
    authorization_url = append_query_parameter(uris.authentication_uri, "redirect_uri", REDIRECT_URI)
    trace.info("Authorization URI obtained.")

    cookie_jar = make_cookie_jar()
    runner = LoginFlowRunner(cookie_jar=cookie_jar, trace=trace, language=language)
    result = runner.run_start(
        authorization_url=authorization_url,
        username=credentials.username,
        password=credentials.password,
    )

    if result.pending_code_form is not None:
        transaction_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)
        meta = TransactionMeta(
            transaction_id=transaction_id,
            created_at=time.time(),
            expires_at=time.time() + TRANSACTION_TTL_SECONDS,
            oauth_state=uris.state,
            redirect_uri=REDIRECT_URI,
            device_id=device_id,
            device_token=device_token,
            pending_form={
                "method": result.pending_code_form.form.method,
                "action_url": result.pending_code_form.form.action_url,
                "payload_fields": result.pending_code_form.form.payload_fields,
                "controls": [asdict(control) for control in result.pending_code_form.form.controls],
                "code_field": result.pending_code_form.code_field,
            },
            observed_redirect_uris=list(result.observed_redirect_uris),
        )
        tx_path = save_transaction(home, meta, cookie_jar, trace)
        print(
            f"NEEDS_EMAIL_CODE transaction_id={transaction_id} expires_in={TRANSACTION_TTL_SECONDS}s "
            f"state_dir={tx_path}"
        )
        return 20

    if not result.callback_url:
        raise LoginError("Login ended without callback URL.")

    complete_callback_and_verify(
        callback_url=result.callback_url,
        expected_state=uris.state,
        redirect_uri=REDIRECT_URI,
        device_token=device_token,
        observed_redirect_uris=result.observed_redirect_uris,
        api=api,
    )
    print("RESULT callback_captured=yes")
    print("RESULT state_valid=yes")
    print("RESULT access_token=yes")
    print("RESULT refresh_token=yes")
    print("RESULT profile_verified=yes")
    return 0


def run_resume(*, home: Path, transaction_id: str, otp_code: str, language: str = "ca-ES") -> int:
    """Resume pending OTP transaction and verify token exchange."""
    clean_expired_transactions(home)
    meta, cookie_jar, previous_trace = load_transaction(home, transaction_id)
    trace = TracePrinter(verbose=True)
    if previous_trace:
        trace.info("Resuming transaction with existing trace context.")
        for line in previous_trace:
            trace.info(f"PREV {line}")

    pending_form = pending_form_from_meta(meta.pending_form)
    runner = LoginFlowRunner(cookie_jar=cookie_jar, trace=trace, language=language)

    result = runner.run_resume(pending=pending_form, email_code=otp_code)
    if result.pending_code_form is not None:
        meta.pending_form = {
            "method": result.pending_code_form.form.method,
            "action_url": result.pending_code_form.form.action_url,
            "payload_fields": result.pending_code_form.form.payload_fields,
            "controls": [asdict(control) for control in result.pending_code_form.form.controls],
            "code_field": result.pending_code_form.code_field,
        }
        save_transaction(home, meta, cookie_jar, trace)
        raise InvalidEmailCodeError("Email code rejected; transaction updated for retry.")

    if not result.callback_url:
        raise LoginError("Resume phase ended without callback URL.")

    api = MobileApiClient(language=language)
    complete_callback_and_verify(
        callback_url=result.callback_url,
        expected_state=meta.oauth_state,
        redirect_uri=meta.redirect_uri,
        device_token=meta.device_token,
        observed_redirect_uris=meta.observed_redirect_uris,
        api=api,
    )

    delete_transaction(home, transaction_id)
    print("RESULT callback_captured=yes")
    print("RESULT state_valid=yes")
    print("RESULT access_token=yes")
    print("RESULT refresh_token=yes")
    print("RESULT profile_verified=yes")
    return 0


def pending_form_from_meta(raw: dict[str, Any]) -> EmailCodeFormSelection:
    """Rebuild pending OTP form from serialized metadata."""
    controls = [
        FormControl(
            name=str(item.get("name") or ""),
            control_type=str(item.get("control_type") or "text"),
            value=str(item.get("value") or ""),
            field_id=str(item.get("field_id") or ""),
            autocomplete=str(item.get("autocomplete") or ""),
            maxlength=str(item.get("maxlength") or ""),
            placeholder=str(item.get("placeholder") or ""),
        )
        for item in raw.get("controls", [])
    ]
    form = ParsedForm(
        method=str(raw["method"]),
        action_url=str(raw["action_url"]),
        controls=controls,
        payload_fields={str(k): str(v) for k, v in dict(raw.get("payload_fields") or {}).items()},
    )
    return EmailCodeFormSelection(form=form, code_field=str(raw["code_field"]))


def complete_callback_and_verify(
    *,
    callback_url: str,
    expected_state: str,
    redirect_uri: str,
    device_token: str,
    observed_redirect_uris: list[str] | None,
    api: MobileApiClient,
) -> tuple[TokenPair, dict[str, Any]]:
    """Validate callback state, exchange code, and verify profile endpoint."""
    params = parse_callback_params(callback_url)
    if params.error:
        raise LoginError("OAuth callback returned error.")
    if not params.code:
        raise LoginError("OAuth callback did not return authorization code.")
    if not states_match(expected_state, params.state, expected_redirect_uri=redirect_uri):
        raise LoginError("OAuth state mismatch.")

    callback_parsed = urllib.parse.urlparse(callback_url)
    print(
        "DEBUG callback_target="
        f"{callback_parsed.scheme}://{callback_parsed.hostname or callback_parsed.netloc}{callback_parsed.path}"
    )
    print(f"DEBUG code_profile={code_profile(params.code)}")
    if params.raw_code and params.raw_code != (params.code or ""):
        print(f"DEBUG raw_code_profile={code_profile(params.raw_code)}")
    print(f"DEBUG state_profile={state_profile(params.state)}")

    redirect_candidates = infer_redirect_candidates_from_state(
        expected_state=expected_state,
        received_state=params.state,
        default_redirect_uri=redirect_uri,
    )
    callback_candidate = callback_redirect_uri_candidate(callback_url)
    if callback_candidate and callback_candidate not in redirect_candidates:
        redirect_candidates.append(callback_candidate)
    for observed in observed_redirect_uris or []:
        if observed not in redirect_candidates:
            redirect_candidates.append(observed)
    redirect_candidates = expand_redirect_candidate_variants(redirect_candidates)
    print(
        "DEBUG redirect_candidates="
        f"{[sanitize_url_for_log(candidate) for candidate in redirect_candidates]}"
    )

    code_candidates = [params.code]
    if params.raw_code and params.raw_code not in code_candidates:
        code_candidates.append(params.raw_code)

    pair: TokenPair | None = None
    last_error: ApiError | None = None
    attempt_summaries: list[str] = []
    for code_candidate in code_candidates:
        for candidate in redirect_candidates:
            try:
                pair = api.exchange_authorization_code(
                    code_candidate,
                    device_token=device_token,
                    redirect_uri=candidate,
                )
                code_tag = "raw" if code_candidate == params.raw_code and params.raw_code != params.code else "decoded"
                attempt_summaries.append(f"{code_tag}@{sanitize_url_for_log(candidate)}:ok")
                break
            except ApiError as err:
                last_error = err
                code_tag = "raw" if code_candidate == params.raw_code and params.raw_code != params.code else "decoded"
                attempt_summaries.append(
                    f"{code_tag}@{sanitize_url_for_log(candidate)}:error:{err.status_code or 'unknown'}"
                )
        if pair is not None:
            break

    if pair is None:
        if last_error is not None:
            details = ", ".join(attempt_summaries)
            raise ApiError(
                f"{last_error} (exchange attempts={details})",
                status_code=last_error.status_code,
            ) from last_error
        raise LoginError("Authorization code exchange failed.")

    profile = api.get_user_current(pair.access_token)
    if not isinstance(profile, dict):
        raise ApiError("Profile verification failed.")
    return pair, profile


def code_profile(code: str) -> str:
    """Return safe characteristics of an authorization code without exposing value."""
    return (
        f"len={len(code)}"
        f",space={'yes' if ' ' in code else 'no'}"
        f",plus={'yes' if '+' in code else 'no'}"
        f",slash={'yes' if '/' in code else 'no'}"
        f",eq={'yes' if '=' in code else 'no'}"
        f",pct={'yes' if '%' in code else 'no'}"
    )


def state_profile(state: str) -> str:
    """Return safe characteristics of a state value without exposing content."""
    if state.startswith("mobile_"):
        prefix = "mobile"
    elif state.startswith("web__"):
        prefix = "web"
    else:
        prefix = "plain"
    return f"kind={prefix},len={len(state)}"


def expand_redirect_candidate_variants(candidates: list[str]) -> list[str]:
    """Expand redirect URI candidates with small safe variants for interoperability."""
    expanded: list[str] = []

    def add(value: str) -> None:
        if value and value not in expanded:
            expanded.append(value)

    for candidate in candidates:
        add(candidate)

        parsed = urllib.parse.urlparse(candidate)
        if parsed.path.endswith("/"):
            add(urllib.parse.urlunparse(parsed._replace(path=parsed.path.rstrip("/"))))

        if parsed.scheme == MOBILE_SCHEME and parsed.netloc == "login" and parsed.path in {"", "/"}:
            add("bonpreu-atm://login")

        if parsed.scheme == "https" and parsed.hostname == INTERMEDIATE_HOST and parsed.path == "/sso-login":
            add("https://www.compraonline.bonpreuesclat.cat/sso-login/auth")

        if parsed.scheme == "https" and parsed.hostname == INTERMEDIATE_HOST and parsed.path == "/sso-login/auth":
            add("https://www.compraonline.bonpreuesclat.cat/sso-login")

    return expanded


def callback_redirect_uri_candidate(callback_url: str) -> str | None:
    """Return callback base URI candidate for token exchange when callback is web intermediary."""
    parsed = urllib.parse.urlparse(callback_url)
    if parsed.scheme == "https" and parsed.hostname == INTERMEDIATE_HOST and parsed.path in INTERMEDIATE_PATHS:
        sanitized = parsed._replace(query="", fragment="")
        return urllib.parse.urlunparse(sanitized)
    return None


def sanitize_url_for_log(url: str) -> str:
    """Return URL without query/fragment for safe diagnostics."""
    parsed = urllib.parse.urlparse(url)
    sanitized = parsed._replace(query="", fragment="")
    return urllib.parse.urlunparse(sanitized)


def command_credentials_store(args: argparse.Namespace) -> int:
    """Handle `credentials store` command."""
    home = probe_home_dir()
    path = store_credentials_file(
        home,
        username=args.username,
        password=args.password,
        override=args.credentials_file,
    )
    print(f"Credentials saved to {path}")
    return 0


def command_start(args: argparse.Namespace) -> int:
    """Handle `start` command."""
    return run_start(
        home=probe_home_dir(),
        language=args.language,
        credentials_file=args.credentials_file,
        use_alternative_mobile=args.alternative_mobile,
    )


def command_resume(args: argparse.Namespace) -> int:
    """Handle `resume` command."""
    transaction_id = args.transaction_id
    if not transaction_id:
        raise ProbeError("--transaction-id is required")

    otp = (args.otp or "").strip()
    if args.otp_stdin:
        otp = (sys.stdin.readline() or "").strip()
    if not otp:
        raise ProbeError("OTP code is required. Use --otp or --otp-stdin.")

    return run_resume(
        home=probe_home_dir(),
        transaction_id=transaction_id,
        otp_code=otp,
        language=args.language,
    )


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser."""
    parser = argparse.ArgumentParser(description="Bonpreu standalone auth probe")
    subparsers = parser.add_subparsers(dest="command", required=True)

    cred = subparsers.add_parser("credentials", help="manage stored credentials")
    cred_sub = cred.add_subparsers(dest="credentials_command", required=True)
    cred_store = cred_sub.add_parser("store", help="store username/password in local credentials file")
    cred_store.add_argument("--username", required=True, help="Bonpreu account email")
    cred_store.add_argument("--password", required=True, help="Bonpreu account password")
    cred_store.add_argument(
        "--credentials-file",
        default="",
        help="credentials JSON path (default: ~/.bonpreu-auth-probe/credentials.json)",
    )
    cred_store.set_defaults(func=command_credentials_store)

    start = subparsers.add_parser("start", help="start full login flow until OTP or success")
    start.add_argument("--language", default="ca-ES", help="Accept-Language header (default: ca-ES)")
    start.add_argument(
        "--credentials-file",
        default="",
        help="credentials JSON path (default: ~/.bonpreu-auth-probe/credentials.json)",
    )
    start.add_argument(
        "--alternative-mobile",
        action="store_true",
        help="use v1/authorize/uris/alternative-mobile",
    )
    start.set_defaults(func=command_start)

    resume = subparsers.add_parser("resume", help="resume OTP phase")
    resume.add_argument("--transaction-id", required=True, help="pending transaction identifier")
    resume.add_argument("--otp", default="", help="email verification code")
    resume.add_argument("--otp-stdin", action="store_true", help="read OTP code from stdin")
    resume.add_argument("--language", default="ca-ES", help="Accept-Language header (default: ca-ES)")
    resume.set_defaults(func=command_resume)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Program entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return int(args.func(args))
    except InvalidCredentialsError as err:
        print(f"ERROR invalid_credentials: {err}")
        return 11
    except InvalidEmailCodeError as err:
        print(f"ERROR invalid_email_code: {err}")
        return 12
    except ChallengeRequiredError as err:
        print(f"ERROR browser_challenge_required: {err}")
        return 13
    except ExpiredTransactionError as err:
        print(f"ERROR transaction_expired: {err}")
        return 14
    except ProbeError as err:
        print(f"ERROR probe: {err}")
        return 1
    except Exception as err:  # pragma: no cover - defensive fallback
        print(f"ERROR unexpected: {err.__class__.__name__}")
        return 99


if __name__ == "__main__":
    raise SystemExit(main())
