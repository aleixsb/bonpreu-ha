"""Tests for auth code exchange behavior in API client."""

from __future__ import annotations

import asyncio
import sys
import types
import unittest
from typing import Any


def _install_homeassistant_stubs() -> None:
    if "homeassistant" in sys.modules:
        return

    homeassistant = types.ModuleType("homeassistant")
    homeassistant.__path__ = []
    config_entries = types.ModuleType("homeassistant.config_entries")
    const = types.ModuleType("homeassistant.const")
    core = types.ModuleType("homeassistant.core")
    aiohttp_client = types.ModuleType("homeassistant.helpers.aiohttp_client")

    class ConfigEntry:
        pass

    class Platform:
        SENSOR = "sensor"
        TODO = "todo"

    class HomeAssistant:
        pass

    config_entries.ConfigEntry = ConfigEntry
    const.CONF_LANGUAGE = "language"
    const.Platform = Platform
    core.HomeAssistant = HomeAssistant
    aiohttp_client.async_get_clientsession = lambda hass: None

    sys.modules["homeassistant"] = homeassistant
    sys.modules["homeassistant.config_entries"] = config_entries
    sys.modules["homeassistant.const"] = const
    sys.modules["homeassistant.core"] = core
    sys.modules["homeassistant.helpers"] = types.ModuleType("homeassistant.helpers")
    sys.modules["homeassistant.helpers.aiohttp_client"] = aiohttp_client


def _install_aiohttp_stubs() -> None:
    if "aiohttp" in sys.modules:
        aiohttp = sys.modules["aiohttp"]
    else:
        aiohttp = types.ModuleType("aiohttp")

    class ClientError(Exception):
        pass

    class ClientTimeout:
        def __init__(self, total=None) -> None:
            self.total = total

    class ClientSession:
        pass

    aiohttp.ClientError = ClientError
    aiohttp.ClientTimeout = ClientTimeout
    aiohttp.ClientSession = ClientSession
    sys.modules["aiohttp"] = aiohttp


_install_homeassistant_stubs()
_install_aiohttp_stubs()

from custom_components.bonpreu.api.auth import format_auth_header_value
from custom_components.bonpreu.api.client import BonpreuApiClient
from custom_components.bonpreu.api.exceptions import BonpreuApiError, BonpreuAuthError


class _FakeBonpreuApiClient(BonpreuApiClient):
    def __init__(self, *, outcomes: list[Any], device_token: str | None) -> None:
        super().__init__(
            session=object(),
            language="ca-ES",
            device_token=device_token,
        )
        self.outcomes = list(outcomes)
        self.calls: list[dict[str, Any]] = []

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append(
            {
                "method": method,
                "path": path,
                "kwargs": kwargs,
            }
        )
        if not self.outcomes:
            raise AssertionError("No fake outcome left for request.")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class ApiClientAuthExchangeTests(unittest.TestCase):
    def test_exchange_retries_with_raw_device_header(self) -> None:
        device_token = "abc+def=="
        client = _FakeBonpreuApiClient(
            outcomes=[
                BonpreuApiError("HTTP 500 for v1/authorize", status_code=500),
                {"token": "access-token", "refreshToken": "refresh-token"},
            ],
            device_token=device_token,
        )

        pair = asyncio.run(client.exchange_authorization_code("code-1", "bonpreu-atm://login"))

        self.assertEqual(pair.access_token, "access-token")
        self.assertEqual(pair.refresh_token, "refresh-token")
        self.assertEqual(len(client.calls), 2)
        self.assertEqual(client.calls[0]["method"], "POST")
        self.assertEqual(client.calls[0]["path"], "v1/authorize")
        self.assertEqual(
            client.calls[0]["kwargs"]["headers"]["Authorization"],
            format_auth_header_value(device_token),
        )
        self.assertEqual(
            client.calls[1]["kwargs"]["headers"]["Authorization"],
            f"token:{device_token}",
        )
        self.assertEqual(
            client.calls[0]["kwargs"]["json"],
            {
                "authorizationCode": "code-1",
                "redirectUri": "bonpreu-atm://login",
            },
        )

    def test_exchange_deduplicates_identical_header_candidates(self) -> None:
        device_token = "abc123"
        client = _FakeBonpreuApiClient(
            outcomes=[{"token": "access-token"}],
            device_token=device_token,
        )

        pair = asyncio.run(client.exchange_authorization_code("code-1", "bonpreu-atm://login"))

        self.assertEqual(pair.access_token, "access-token")
        self.assertIsNone(pair.refresh_token)
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(
            client.calls[0]["kwargs"]["headers"]["Authorization"],
            "token:abc123",
        )

    def test_exchange_requires_device_token(self) -> None:
        client = _FakeBonpreuApiClient(outcomes=[], device_token=None)
        with self.assertRaises(BonpreuAuthError):
            asyncio.run(client.exchange_authorization_code("code-1", "bonpreu-atm://login"))

    def test_exchange_rejects_non_dict_payload(self) -> None:
        client = _FakeBonpreuApiClient(outcomes=[["invalid"]], device_token="abc123")
        with self.assertRaises(BonpreuApiError):
            asyncio.run(client.exchange_authorization_code("code-1", "bonpreu-atm://login"))

    def test_exchange_rejects_missing_access_token(self) -> None:
        client = _FakeBonpreuApiClient(outcomes=[{"refreshToken": "r1"}], device_token="abc123")
        with self.assertRaises(BonpreuApiError):
            asyncio.run(client.exchange_authorization_code("code-1", "bonpreu-atm://login"))


if __name__ == "__main__":
    unittest.main()
