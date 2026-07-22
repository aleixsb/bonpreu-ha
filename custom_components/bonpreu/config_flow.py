"""Config flow for Bonpreu integration."""

from __future__ import annotations

import logging
import uuid

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import homeassistant.helpers.config_validation as cv

from .api.auth import (
    append_query_parameter,
    is_expected_callback_url,
    is_intermediate_callback_url,
    parse_callback_query,
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
from .oauth_callback import (
    async_register_oauth_callback_view,
    async_try_build_flow_callback_url,
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
        self._mobile_redirect_uri: str = REDIRECT_URI
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
        self._redirect_uri = REDIRECT_URI
        self._use_alternative_mobile = bool(entry.data.get(CONF_USE_ALTERNATIVE_MOBILE, False))
        self._attempted_authorization_codes.clear()

        errors = await self._async_prepare_authorization_url(reuse_device=True)
        if errors:
            if errors.get("base") != "no_ha_url":
                return self.async_abort(reason="cannot_connect")
            return self._show_callback_form(errors)

        return await self.async_step_callback()

    async def async_step_user(self, user_input: dict | None = None):
        """First step: prepare OAuth URL."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._use_alternative_mobile = bool(user_input.get(CONF_USE_ALTERNATIVE_MOBILE, False))
            self._title = user_input.get("title") or "Bonpreu"
            self._redirect_uri = REDIRECT_URI
            self._device_id = None
            self._device_token = None
            self._attempted_authorization_codes.clear()
            errors = await self._async_prepare_authorization_url(reuse_device=False)

            if not errors:
                return await self.async_step_callback()
            if errors.get("base") == "no_ha_url" and self._authorization_url:
                return self._show_callback_form(errors)

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
            callback_url = str(user_input[CONF_CALLBACK_URL]).strip()
            matched_redirect_uri: str | None = None

            if is_intermediate_callback_url(callback_url):
                try:
                    params = parse_callback_query(callback_url)
                except BonpreuConfigError:
                    errors["base"] = "invalid_callback_url"
                    return self._show_callback_form(errors)
            elif is_expected_callback_url(callback_url, expected_redirect_uri=self._redirect_uri):
                matched_redirect_uri = self._redirect_uri
                try:
                    params = parse_callback_url(callback_url, expected_redirect_uri=self._redirect_uri)
                except BonpreuConfigError:
                    errors["base"] = "invalid_callback_url"
                    return self._show_callback_form(errors)
            elif is_expected_callback_url(callback_url, expected_redirect_uri=self._mobile_redirect_uri):
                matched_redirect_uri = self._mobile_redirect_uri
                try:
                    params = parse_callback_url(
                        callback_url,
                        expected_redirect_uri=self._mobile_redirect_uri,
                    )
                except BonpreuConfigError:
                    errors["base"] = "invalid_callback_url"
                    return self._show_callback_form(errors)
            else:
                errors["base"] = "invalid_callback_url"
                return self._show_callback_form(errors)

            redirect_uri_for_exchange = self._matching_redirect_uri(
                params.state,
                preferred_redirect_uri=matched_redirect_uri,
            )
            if redirect_uri_for_exchange is None:
                errors["base"] = "state_mismatch"
            elif params.error:
                errors["base"] = "auth_declined"
            elif not params.code:
                errors["base"] = "invalid_callback_url"
            elif params.code in self._attempted_authorization_codes:
                errors["base"] = "auth_retry_requires_new_login"
            else:
                self._attempted_authorization_codes.add(params.code)
                session = async_get_clientsession(self.hass)
                client = BonpreuApiClient(
                    session,
                    language=self.hass.config.language or "es",
                    device_token=self._device_token,
                )
                try:
                    token_pair = await client.exchange_authorization_code(
                        params.code,
                        redirect_uri_for_exchange,
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

                    if self._reauth_entry is not None:
                        existing_customer_id = str(
                            self._reauth_entry.data.get(CONF_RETAILER_CUSTOMER_ID) or ""
                        ).strip()
                        if (
                            existing_customer_id
                            and retailer_customer_id
                            and existing_customer_id != retailer_customer_id
                        ):
                            return self.async_abort(reason="reauth_account_mismatch")

                    data = {
                        CONF_ACCESS_TOKEN: token_pair.access_token,
                        CONF_REFRESH_TOKEN: token_pair.refresh_token,
                        CONF_DEVICE_ID: self._device_id,
                        CONF_DEVICE_TOKEN: self._device_token,
                        CONF_REDIRECT_URI: REDIRECT_URI,
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

    async def _async_prepare_authorization_url(self, *, reuse_device: bool) -> dict[str, str]:
        """Prepare device token and OAuth URL for current flow."""
        errors: dict[str, str] = {}
        session = async_get_clientsession(self.hass)
        client = BonpreuApiClient(session, language=self.hass.config.language or "es")

        try:
            async_register_oauth_callback_view(self.hass)
        except RuntimeError:
            errors["base"] = "cannot_connect"
            return errors

        if not reuse_device or not self._device_id:
            self._device_id = str(uuid.uuid4())
            self._device_token = None

        try:
            if not self._device_token:
                self._device_token = await client.ensure_device_token(self._device_id)
            client.set_device_token(self._device_token)
        except BonpreuApiError as err:
            _LOGGER.error("Could not initialize device token flow: %s", err)
            errors["base"] = "device_token_failed"
            return errors

        try:
            uris = await client.get_oauth_uris(
                use_alternative_mobile=self._use_alternative_mobile,
            )
        except BonpreuApiError as err:
            _LOGGER.error("Could not fetch OAuth URIs: %s", err)
            errors["base"] = "cannot_connect"
            return errors

        self._oauth_state = uris.state

        callback_redirect_uri = async_try_build_flow_callback_url(self.hass, self.flow_id)
        if callback_redirect_uri is None:
            self._redirect_uri = self._mobile_redirect_uri
            self._authorization_url = append_query_parameter(
                uris.authentication_uri,
                "redirect_uri",
                self._redirect_uri,
            )
            errors["base"] = "no_ha_url"
            return errors

        self._redirect_uri = callback_redirect_uri
        self._authorization_url = append_query_parameter(
            uris.authentication_uri,
            "redirect_uri",
            self._redirect_uri,
        )
        return errors

    def _matching_redirect_uri(
        self,
        received_state: str,
        *,
        preferred_redirect_uri: str | None = None,
    ) -> str | None:
        """Return redirect URI matching wrapped OAuth state."""
        candidates: list[str] = []
        for candidate in (preferred_redirect_uri, self._redirect_uri, self._mobile_redirect_uri):
            if candidate and candidate not in candidates:
                candidates.append(candidate)

        for candidate in candidates:
            if states_match(
                self._oauth_state,
                received_state,
                expected_redirect_uri=candidate,
            ):
                return candidate
        return None

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
