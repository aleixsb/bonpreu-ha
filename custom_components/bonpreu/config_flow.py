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
    is_intermediate_callback_url,
    parse_callback_query,
    parse_callback_url,
    states_match,
)
from .api.client import BonpreuApiClient
from .api.exceptions import (
    BonpreuApiError,
    BonpreuConfigError,
    BonpreuInvalidCredentialsError,
    BonpreuInvalidEmailCodeError,
    BonpreuLoginChallengeError,
    BonpreuLoginError,
    BonpreuLoginExpiredError,
    BonpreuLoginFormError,
)
from .api.login import BonpreuCredentialLoginTransaction
from .const import (
    CONF_ACCESS_TOKEN,
    CONF_CALLBACK_URL,
    CONF_DEVICE_ID,
    CONF_DEVICE_TOKEN,
    CONF_EMAIL_CODE,
    CONF_REDIRECT_URI,
    CONF_REFRESH_TOKEN,
    CONF_RETAILER_CUSTOMER_ID,
    CONF_UPDATE_INTERVAL_MINUTES,
    CONF_USE_ALTERNATIVE_MOBILE,
    CONF_USE_MOBILE_REDIRECT,
    DATA_STATIC_CREDENTIALS,
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
        self._credential_login: BonpreuCredentialLoginTransaction | None = None

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
            return self.async_abort(reason="cannot_connect")

        automatic = await self._async_try_credential_login_start()
        if automatic is not None:
            return automatic

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
                automatic = await self._async_try_credential_login_start()
                if automatic is not None:
                    return automatic
                return await self.async_step_callback()

        schema = vol.Schema(
            {
                vol.Optional("title", default="Bonpreu"): cv.string,
                vol.Optional(CONF_USE_ALTERNATIVE_MOBILE, default=False): bool,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_email_code(self, user_input: dict | None = None):
        """Submit Bonpreu email verification code for credential login."""
        errors: dict[str, str] = {}
        if self._credential_login is None:
            return await self._async_fallback_to_manual({"base": "automated_session_expired"})

        if user_input is not None:
            code = str(user_input.get(CONF_EMAIL_CODE) or "").strip()
            if not code:
                errors["base"] = "invalid_email_code"
            else:
                try:
                    progress = await self._credential_login.async_submit_email_code(code)
                except BonpreuInvalidEmailCodeError:
                    errors["base"] = "invalid_email_code"
                except BonpreuInvalidCredentialsError:
                    return await self._async_fallback_to_manual({"base": "invalid_credentials"})
                except BonpreuLoginExpiredError:
                    return await self._async_fallback_to_manual({"base": "automated_session_expired"})
                except (BonpreuLoginChallengeError, BonpreuLoginFormError, BonpreuLoginError):
                    return await self._async_fallback_to_manual({"base": "automated_login_unavailable"})
                else:
                    if progress.callback_url:
                        await self._async_close_credential_login()
                        return await self._async_process_callback_url(progress.callback_url)

                    if progress.email_code_required:
                        return self._show_email_code_form(errors)

                    return await self._async_fallback_to_manual({"base": "automated_login_unavailable"})

        return self._show_email_code_form(errors)

    async def async_step_callback(self, user_input: dict | None = None):
        """Manual fallback: user pastes callback URL with code/state."""
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
            callback_url = str(user_input.get(CONF_CALLBACK_URL) or "").strip()
            return await self._async_process_callback_url(callback_url)

        return self._show_callback_form(errors)

    def _show_email_code_form(self, errors: dict[str, str]):
        """Render email verification input form."""
        schema = vol.Schema({vol.Required(CONF_EMAIL_CODE): cv.string})
        return self.async_show_form(
            step_id="email_code",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "authorization_url": self._authorization_url or "",
            },
        )

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

    async def _async_try_credential_login_start(self):
        """Try automatic login using YAML credentials, return flow result or None."""
        credentials = self._resolve_static_credentials()
        if credentials is None:
            return await self._async_fallback_to_manual({"base": "credentials_not_configured"})

        await self._async_close_credential_login()
        username, password = credentials
        self._credential_login = BonpreuCredentialLoginTransaction(
            username=username,
            password=password,
            language=self.hass.config.language or "ca-ES",
        )

        try:
            progress = await self._credential_login.async_start(self._authorization_url or "")
        except BonpreuInvalidCredentialsError:
            return await self._async_fallback_to_manual({"base": "invalid_credentials"})
        except BonpreuLoginExpiredError:
            return await self._async_fallback_to_manual({"base": "automated_session_expired"})
        except (BonpreuLoginChallengeError, BonpreuLoginFormError, BonpreuLoginError):
            return await self._async_fallback_to_manual({"base": "automated_login_unavailable"})

        if progress.email_code_required:
            return self._show_email_code_form({})

        if progress.callback_url:
            await self._async_close_credential_login()
            return await self._async_process_callback_url(progress.callback_url)

        return await self._async_fallback_to_manual({"base": "automated_login_unavailable"})

    async def _async_fallback_to_manual(self, errors: dict[str, str]):
        """Close automated login state and show manual callback step."""
        await self._async_close_credential_login()
        return self._show_callback_form(errors)

    async def _async_close_credential_login(self) -> None:
        """Close any active credential-login transaction."""
        if self._credential_login is None:
            return
        try:
            await self._credential_login.async_close()
        finally:
            self._credential_login = None

    async def _async_process_callback_url(self, callback_url: str):
        """Parse callback URL and continue token exchange flow."""
        if is_intermediate_callback_url(callback_url):
            try:
                params = parse_callback_query(callback_url)
            except BonpreuConfigError:
                return self._show_callback_form({"base": "invalid_callback_url"})
        else:
            try:
                params = parse_callback_url(
                    callback_url,
                    expected_redirect_uri=self._redirect_uri,
                )
            except BonpreuConfigError:
                return self._show_callback_form({"base": "invalid_callback_url"})

        return await self._async_process_callback_params(params)

    async def _async_process_callback_params(self, params):
        """Exchange callback code and create/update entry."""
        errors: dict[str, str] = {}

        if not states_match(self._oauth_state or "", params.state, expected_redirect_uri=self._redirect_uri):
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

                if self._reauth_entry is not None:
                    existing_customer_id = str(
                        self._reauth_entry.data.get(CONF_RETAILER_CUSTOMER_ID) or ""
                    ).strip()
                    if existing_customer_id and retailer_customer_id and existing_customer_id != retailer_customer_id:
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

                await self._async_close_credential_login()

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

    async def _async_prepare_authorization_url(self, *, reuse_device: bool) -> dict[str, str]:
        """Prepare device token and OAuth URL for current flow."""
        errors: dict[str, str] = {}
        session = async_get_clientsession(self.hass)
        client = BonpreuApiClient(session, language=self.hass.config.language or "es")

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
        self._redirect_uri = REDIRECT_URI
        self._authorization_url = append_query_parameter(
            uris.authentication_uri,
            "redirect_uri",
            self._redirect_uri,
        )
        return errors

    def _resolve_static_credentials(self) -> tuple[str, str] | None:
        """Read username/password from YAML config stored at startup."""
        domain_data = self.hass.data.get(DOMAIN)
        if not isinstance(domain_data, dict):
            return None

        credentials = domain_data.get(DATA_STATIC_CREDENTIALS)
        username = str(getattr(credentials, "username", "") or "").strip()
        password = str(getattr(credentials, "password", "") or "").strip()
        if not username or not password:
            return None
        return username, password

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
