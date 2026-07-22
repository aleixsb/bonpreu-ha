"""Bonpreu integration setup."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_LANGUAGE, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

try:
    import voluptuous as vol
    import homeassistant.helpers.config_validation as cv
except ModuleNotFoundError:  # pragma: no cover - lightweight unit-test stubs
    vol = None  # type: ignore[assignment]
    cv = None  # type: ignore[assignment]

from .api.client import BonpreuApiClient
from .const import (
    CONF_ACCESS_TOKEN,
    CONF_DEVICE_TOKEN,
    CONF_PASSWORD,
    CONF_REFRESH_TOKEN,
    CONF_USERNAME,
    DATA_STATIC_CREDENTIALS,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.TODO]


@dataclass(slots=True)
class BonpreuStaticCredentials:
    """Credentials resolved from Home Assistant YAML configuration."""

    username: str
    password: str


if vol is not None and cv is not None:
    CONFIG_SCHEMA = vol.Schema(
        {
            vol.Optional(DOMAIN): vol.Schema(
                {
                    vol.Required(CONF_USERNAME): cv.string,
                    vol.Required(CONF_PASSWORD): cv.string,
                }
            )
        },
        extra=vol.ALLOW_EXTRA,
    )
else:
    CONFIG_SCHEMA = {}


async def async_setup(hass: HomeAssistant, config: dict[str, Any]) -> bool:
    """Set up Bonpreu integration."""
    domain_data = hass.data.setdefault(DOMAIN, {})

    credentials = _extract_static_credentials(config)
    if credentials is not None:
        domain_data[DATA_STATIC_CREDENTIALS] = credentials
    else:
        domain_data.pop(DATA_STATIC_CREDENTIALS, None)

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Bonpreu from config entry."""
    from .coordinator import BonpreuDataUpdateCoordinator
    from .runtime import BonpreuRuntimeData
    from .services import async_register_services

    session = async_get_clientsession(hass)
    language = hass.config.language or hass.config.as_dict().get(CONF_LANGUAGE, "es")

    async def _on_token_refresh(access_token: str, refresh_token: str | None) -> None:
        effective_refresh_token = refresh_token
        if effective_refresh_token is None:
            effective_refresh_token = entry.data.get(CONF_REFRESH_TOKEN)

        new_data = {
            **entry.data,
            CONF_ACCESS_TOKEN: access_token,
            CONF_REFRESH_TOKEN: effective_refresh_token,
        }
        hass.config_entries.async_update_entry(entry, data=new_data)

    client = BonpreuApiClient(
        session,
        language=language,
        access_token=entry.data.get(CONF_ACCESS_TOKEN),
        refresh_token=entry.data.get(CONF_REFRESH_TOKEN),
        device_token=entry.data.get(CONF_DEVICE_TOKEN),
        on_token_refresh=_on_token_refresh,
    )

    coordinator = BonpreuDataUpdateCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()

    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    hass.data[DOMAIN][entry.entry_id] = BonpreuRuntimeData(
        client=client,
        coordinator=coordinator,
    )

    await async_register_services(hass)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    _LOGGER.debug("Bonpreu entry %s set up", entry.entry_id)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload Bonpreu config entry."""
    from .services import async_unregister_services

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        await async_unregister_services(hass)
    return unload_ok


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options updates by reloading the config entry."""
    await hass.config_entries.async_reload(entry.entry_id)


def _extract_static_credentials(config: dict[str, Any]) -> BonpreuStaticCredentials | None:
    """Return configured YAML credentials if present."""
    raw_domain_config = config.get(DOMAIN)
    if not isinstance(raw_domain_config, dict):
        return None

    username = str(raw_domain_config.get(CONF_USERNAME) or "").strip()
    password = str(raw_domain_config.get(CONF_PASSWORD) or "").strip()
    if not username or not password:
        return None

    return BonpreuStaticCredentials(username=username, password=password)
