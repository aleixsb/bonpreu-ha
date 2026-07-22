"""OAuth callback helpers for Bonpreu config flow."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import secrets
import time

from aiohttp import web

from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import UnknownFlow
from homeassistant.helpers.network import NoURLAvailableError, get_url

from .const import (
    CONF_CALLBACK_URL,
    DATA_OAUTH,
    DATA_OAUTH_PENDING,
    DATA_OAUTH_VIEW_REGISTERED,
    OAUTH_CALLBACK_PATH,
    OAUTH_CALLBACK_TTL_SECONDS,
)

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class PendingOAuthCallback:
    """One-time callback routing data for a single flow."""

    flow_id: str
    redirect_uri: str
    created_at: float


class BonpreuOAuthCallbackView(HomeAssistantView):
    """Receive browser redirect and resume config flow."""

    requires_auth = False
    name = "bonpreu:oauth_callback"
    url = f"{OAUTH_CALLBACK_PATH}/{{nonce}}"

    async def get(self, request: web.Request, nonce: str) -> web.Response:
        """Handle OAuth callback from browser redirect."""
        hass: HomeAssistant = request.app["hass"]
        pending = _peek_pending_callback(hass, nonce)
        if pending is None:
            return _html_response(
                "Authentication session expired. Return to Home Assistant and restart login.",
                status=400,
            )

        try:
            state = _read_single_query_value(request.query, "state")
            code = _read_single_query_value(request.query, "code")
            error = _read_single_query_value(request.query, "error")
        except ValueError:
            return _html_response("Invalid callback query parameters.", status=400)

        if not state:
            return _html_response("Missing state parameter.", status=400)

        if not code and not error:
            return _html_response("Missing code or error parameter.", status=400)

        pending = _consume_pending_callback(hass, nonce)
        if pending is None:
            return _html_response(
                "Authentication session expired. Return to Home Assistant and restart login.",
                status=400,
            )

        callback_url = pending.redirect_uri
        if request.query_string:
            callback_url = f"{callback_url}?{request.query_string}"

        try:
            await hass.config_entries.flow.async_configure(
                flow_id=pending.flow_id,
                user_input={CONF_CALLBACK_URL: callback_url},
            )
        except UnknownFlow:
            return _html_response(
                "Authentication flow no longer exists. Return to Home Assistant and retry login.",
                status=400,
            )
        except Exception:  # pragma: no cover - unexpected framework error
            _LOGGER.exception("Could not resume Bonpreu config flow from OAuth callback")
            return _html_response(
                "Authentication failed while returning to Home Assistant. Please retry login.",
                status=500,
            )

        return _html_response("Authentication completed. You can close this window.")


def async_register_oauth_callback_view(hass: HomeAssistant) -> None:
    """Ensure callback view is registered once."""
    domain_data = hass.data.setdefault(DATA_OAUTH, {})
    if domain_data.get(DATA_OAUTH_VIEW_REGISTERED):
        return

    if not hasattr(hass, "http"):
        raise RuntimeError("Home Assistant HTTP component is not available.")

    hass.http.register_view(BonpreuOAuthCallbackView)
    domain_data[DATA_OAUTH_VIEW_REGISTERED] = True


def async_build_flow_callback_url(hass: HomeAssistant, flow_id: str) -> str:
    """Create and store one-time callback URL for a flow."""
    base_url = get_url(
        hass,
        allow_internal=False,
        prefer_external=True,
        require_ssl=True,
    )

    _remove_callbacks_for_flow(hass, flow_id)
    _purge_expired_callbacks(hass)

    nonce = secrets.token_urlsafe(24)
    callback_url = f"{base_url.rstrip('/')}{OAUTH_CALLBACK_PATH}/{nonce}"
    _pending_callbacks(hass)[nonce] = PendingOAuthCallback(
        flow_id=flow_id,
        redirect_uri=callback_url,
        created_at=time.time(),
    )
    return callback_url


def async_try_build_flow_callback_url(hass: HomeAssistant, flow_id: str) -> str | None:
    """Best-effort callback URL generation for manual fallback mode."""
    try:
        return async_build_flow_callback_url(hass, flow_id)
    except (NoURLAvailableError, RuntimeError):
        return None


def _pending_callbacks(hass: HomeAssistant) -> dict[str, PendingOAuthCallback]:
    domain_data = hass.data.setdefault(DATA_OAUTH, {})
    callbacks = domain_data.get(DATA_OAUTH_PENDING)
    if callbacks is None:
        callbacks = {}
        domain_data[DATA_OAUTH_PENDING] = callbacks
    return callbacks


def _peek_pending_callback(hass: HomeAssistant, nonce: str) -> PendingOAuthCallback | None:
    callbacks = _pending_callbacks(hass)
    _purge_expired_callbacks(hass)
    return callbacks.get(nonce)


def _consume_pending_callback(hass: HomeAssistant, nonce: str) -> PendingOAuthCallback | None:
    callbacks = _pending_callbacks(hass)
    _purge_expired_callbacks(hass)
    return callbacks.pop(nonce, None)


def _purge_expired_callbacks(hass: HomeAssistant) -> None:
    callbacks = _pending_callbacks(hass)
    now = time.time()
    stale = [
        nonce
        for nonce, pending in callbacks.items()
        if (now - pending.created_at) > OAUTH_CALLBACK_TTL_SECONDS
    ]
    for nonce in stale:
        callbacks.pop(nonce, None)


def _remove_callbacks_for_flow(hass: HomeAssistant, flow_id: str) -> None:
    callbacks = _pending_callbacks(hass)
    to_remove = [nonce for nonce, pending in callbacks.items() if pending.flow_id == flow_id]
    for nonce in to_remove:
        callbacks.pop(nonce, None)


def _html_response(message: str, *, status: int = 200) -> web.Response:
    html = (
        "<html><head><meta charset='utf-8'><title>Bonpreu Login</title></head>"
        f"<body><p>{message}</p><script>window.close()</script></body></html>"
    )
    return web.Response(text=html, status=status, content_type="text/html")


def _read_single_query_value(query: object, key: str) -> str | None:
    values: list[str]

    if hasattr(query, "getall"):
        values = [str(value) for value in query.getall(key, [])]
    else:
        raw = getattr(query, "get", lambda *_: None)(key)
        if raw is None:
            values = []
        elif isinstance(raw, list):
            values = [str(value) for value in raw]
        else:
            values = [str(raw)]

    if len(values) > 1:
        raise ValueError(f"duplicated query parameter: {key}")
    if not values:
        return None
    value = values[0].strip()
    return value or None
