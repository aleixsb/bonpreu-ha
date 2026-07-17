"""Config flow for Bonpreu integration."""

from __future__ import annotations

import logging
import uuid
from urllib.parse import urlparse, urlunparse

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import homeassistant.helpers.config_validation as cv

from .api.auth import (
    append_query_parameter,
    is_intermediate_callback_url,
    is_mobile_callback_url,
    parse_callback_url,
    states_match,
)
from .api.client import BonpreuApiClient
from .api.exceptions import BonpreuApiError, BonpreuConfigError
from .const import (
    CONF_ACCESS_TOKEN,
    CONF_CALLBACK_URL,
    CONF_DEVICE_ID,
    CONF_DEVICE_TOKEN,
    CONF_REDIRECT_URI,
    CONF_REFRESH_TOKEN,
    CONF_RETAILER_CUSTOMER_ID,
    CONF_UPDATE_INTERVAL_MINUTES,
    CONF_USE_ALTERNATIVE_MOBILE,
    CONF_USE_MOBILE_REDIRECT,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
    REDIRECT_URI,
)

_LOGGER = logging.getLogger(__name__)


class BonpreuConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Bonpreu."""

    VERSION = 1

    def __init__(self) -> None:
        self._oauth_state: str | None = None
        self._authorization_url: str | None = None
        self._device_id: str | None = None
        self._device_token: str | None = None
        self._redirect_uri: str = REDIRECT_URI
        self._use_alternative_mobile: bool = False
        self._attempted_authorization_codes: set[str] = set()
        self._title: str = "Bonpreu"
        self._reauth_entry: config_entries.ConfigEntry | None = None

    async def async_step_reauth(self, entry_data: dict[str, str]):
        """Start reauthentication flow for an existing entry."""
        del entry_data

        entry_id = self.context.get("entry_id")
        if not isinstance(entry_id, str):
            return self.async_abort(reason="invalid_auth_state")

        entry = self.hass.config_entries.async_get_entry(entry_id)
        if entry is None:
            return self.async_abort(reason="invalid_auth_state")

        self._reauth_entry = entry
        self._title = entry.title
        self._device_id = entry.data.get(CONF_DEVICE_ID) or str(uuid.uuid4())
        self._device_token = entry.data.get(CONF_DEVICE_TOKEN)
        self._redirect_uri = entry.data.get(CONF_REDIRECT_URI, REDIRECT_URI)
        self._use_alternative_mobile = bool(entry.data.get(CONF_USE_ALTERNATIVE_MOBILE, False))
        self._attempted_authorization_codes.clear()

        session = async_get_clientsession(self.hass)
        client = BonpreuApiClient(session, language=self.hass.config.language or "es")

        try:
            if not self._device_token:
                self._device_token = await client.ensure_device_token(self._device_id)
            client.set_device_token(self._device_token)
            uris = await client.get_oauth_uris(
                use_alternative_mobile=self._use_alternative_mobile,
            )
        except BonpreuApiError as err:
            _LOGGER.error("Could not prepare Bonpreu reauth flow: %s", err)
            return self.async_abort(reason="cannot_connect")

        self._oauth_state = uris.state
        self._authorization_url = append_query_parameter(
            uris.authentication_uri,
            "redirect_uri",
            self._redirect_uri,
        )
        return await self.async_step_callback()

    async def async_step_user(self, user_input: dict | None = None):
        """First step: prepare OAuth URL."""
        errors: dict[str, str] = {}

        if user_input is not None:
            session = async_get_clientsession(self.hass)
            client = BonpreuApiClient(session, language=self.hass.config.language or "es")
            self._use_alternative_mobile = bool(user_input.get(CONF_USE_ALTERNATIVE_MOBILE, False))
            self._title = user_input.get("title") or "Bonpreu"
            self._redirect_uri = REDIRECT_URI
            self._attempted_authorization_codes.clear()

            if not errors:
                try:
                    self._device_id = str(uuid.uuid4())
                    self._device_token = await client.ensure_device_token(self._device_id)
                    client.set_device_token(self._device_token)
                except BonpreuApiError as err:
                    _LOGGER.error("Could not initialize device token flow: %s", err)
                    errors["base"] = "device_token_failed"

            if not errors:
                try:
                    uris = await client.get_oauth_uris(
                        use_alternative_mobile=self._use_alternative_mobile,
                    )
                except BonpreuApiError as err:
                    _LOGGER.error("Could not fetch OAuth URIs: %s", err)
                    errors["base"] = "cannot_connect"
                else:
                    self._oauth_state = uris.state
                    self._authorization_url = append_query_parameter(
                        uris.authentication_uri,
                        "redirect_uri",
                        self._redirect_uri,
                    )
                    return await self.async_step_callback()

        schema = vol.Schema(
            {
                vol.Optional("title", default="Bonpreu"): cv.string,
                vol.Optional(CONF_USE_ALTERNATIVE_MOBILE, default=False): bool,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_callback(self, user_input: dict | None = None):
        """Second step: user pastes callback URL with code/state."""
        errors: dict[str, str] = {}

        if (
            not self._authorization_url
            or not self._oauth_state
            or not self._device_id
            or not self._device_token
            or not self._redirect_uri
        ):
            return self.async_abort(reason="invalid_auth_state")

        if user_input is not None:
            callback_url = user_input[CONF_CALLBACK_URL].strip()
            session = async_get_clientsession(self.hass)
            callback_url, _normalized = await self._normalize_callback_url(session, callback_url)

            if is_intermediate_callback_url(callback_url):
                errors["base"] = "intermediate_callback_url"
                return self._show_callback_form(errors)

            if not is_mobile_callback_url(callback_url, expected_redirect_uri=self._redirect_uri):
                errors["base"] = "invalid_callback_url"
                return self._show_callback_form(errors)

            try:
                params = parse_callback_url(callback_url, expected_redirect_uri=self._redirect_uri)
            except BonpreuConfigError:
                errors["base"] = "invalid_callback_url"
            else:
                if not states_match(
                    self._oauth_state,
                    params.state,
                    expected_redirect_uri=self._redirect_uri,
                ):
                    errors["base"] = "state_mismatch"
                elif params.error:
                    errors["base"] = "auth_declined"
                elif not params.code:
                    errors["base"] = "invalid_callback_url"
                elif params.code in self._attempted_authorization_codes:
                    errors["base"] = "auth_retry_requires_new_login"
                else:
                    self._attempted_authorization_codes.add(params.code)
                    client = BonpreuApiClient(
                        session,
                        language=self.hass.config.language or "es",
                        device_token=self._device_token,
                    )
                    try:
                        token_pair = await client.exchange_authorization_code(
                            params.code,
                            self._redirect_uri,
                        )
                    except BonpreuApiError as err:
                        _LOGGER.error("Authorization code exchange failed: %s", err)
                        errors["base"] = "auth_retry_requires_new_login"
                    else:
                        client.set_tokens(
                            access_token=token_pair.access_token,
                            refresh_token=token_pair.refresh_token,
                        )

                        retailer_customer_id = ""
                        try:
                            profile = await client.get_user_current()
                        except BonpreuApiError as err:
                            _LOGGER.debug("Could not fetch customer profile after login: %s", err)
                        else:
                            retailer_customer_id = str(
                                profile.get("retailerCustomerId")
                                or profile.get("customerId")
                                or profile.get("id")
                                or ""
                            ).strip()

                        if retailer_customer_id and self._reauth_entry is None:
                            await self.async_set_unique_id(f"bonpreu_{retailer_customer_id}")
                            self._abort_if_unique_id_configured()

                        data = {
                            CONF_ACCESS_TOKEN: token_pair.access_token,
                            CONF_REFRESH_TOKEN: token_pair.refresh_token,
                            CONF_DEVICE_ID: self._device_id,
                            CONF_DEVICE_TOKEN: self._device_token,
                            CONF_REDIRECT_URI: self._redirect_uri,
                            CONF_USE_ALTERNATIVE_MOBILE: self._use_alternative_mobile,
                            CONF_USE_MOBILE_REDIRECT: True,
                        }
                        if retailer_customer_id:
                            data[CONF_RETAILER_CUSTOMER_ID] = retailer_customer_id

                        if self._reauth_entry is not None:
                            updated_data = {
                                **self._reauth_entry.data,
                                **data,
                            }
                            self.hass.config_entries.async_update_entry(
                                self._reauth_entry,
                                data=updated_data,
                            )
                            await self.hass.config_entries.async_reload(self._reauth_entry.entry_id)
                            return self.async_abort(reason="reauth_successful")

                        return self.async_create_entry(title=self._title, data=data)

        return self._show_callback_form(errors)

    def _show_callback_form(self, errors: dict[str, str]):
        """Render callback URL input form."""
        schema = vol.Schema({vol.Required(CONF_CALLBACK_URL): cv.string})
        return self.async_show_form(
            step_id="callback",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "authorization_url": self._authorization_url or "",
                "redirect_uri": self._redirect_uri,
            },
        )

    async def _normalize_callback_url(self, session, callback_url: str) -> tuple[str, bool]:
        """Normalize callback URL when user pastes intermediary web SSO URL.

        Desktop browsers can get stuck at `/sso-login?...` because they cannot open
        the custom app URI scheme. In that case we try `/sso-login/auth?...` and
        read the `Location` header that points to `bonpreu-atm://login?...`.
        """
        if not is_intermediate_callback_url(callback_url):
            return callback_url, False

        parsed = urlparse(callback_url)
        target_url = urlunparse(parsed._replace(path="/sso-login/auth"))

        try:
            async with session.get(target_url, allow_redirects=False) as response:
                location = response.headers.get("Location")
        except Exception as err:  # pragma: no cover - network edge case
            _LOGGER.debug("Could not normalize callback via sso-login/auth: %s", err)
            return callback_url, False

        if location and is_mobile_callback_url(location, expected_redirect_uri=self._redirect_uri):
            _LOGGER.debug("Normalized web SSO callback to app callback URI")
            return location, True

        return callback_url, False

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry):
        """Get options flow for this handler."""
        return BonpreuOptionsFlow(config_entry)


class BonpreuOptionsFlow(config_entries.OptionsFlow):
    """Bonpreu options flow."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._config_entry = config_entry

    async def async_step_init(self, user_input: dict | None = None):
        """Manage options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        current_interval = self._config_entry.options.get(
            CONF_UPDATE_INTERVAL_MINUTES,
            int(DEFAULT_UPDATE_INTERVAL.total_seconds() / 60),
        )

        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_UPDATE_INTERVAL_MINUTES,
                    default=current_interval,
                ): vol.All(vol.Coerce(int), vol.Range(min=1, max=60)),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
