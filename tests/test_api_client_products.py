"""Tests for product payload parsing in API client."""

from __future__ import annotations

import sys
import types
import unittest


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

    if not hasattr(aiohttp, "web"):
        class Response:
            def __init__(self, text: str = "", status: int = 200, content_type: str | None = None) -> None:
                self.text = text
                self.status = status
                self.content_type = content_type

        aiohttp.web = types.SimpleNamespace(Response=Response, Request=object)

    sys.modules["aiohttp"] = aiohttp


_install_homeassistant_stubs()
_install_aiohttp_stubs()

from custom_components.bonpreu.api.client import _parse_products_payload


class ParseProductsPayloadTests(unittest.TestCase):
    def test_parses_direct_list_payload(self) -> None:
        payload = [{"productId": "1", "name": "Milk"}, {"productId": "2", "name": "Eggs"}]
        parsed = _parse_products_payload(payload)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["name"], "Milk")

    def test_parses_products_key_payload(self) -> None:
        payload = {"products": [{"productId": "3", "name": "Bread"}]}
        parsed = _parse_products_payload(payload)
        self.assertEqual(parsed, [{"productId": "3", "name": "Bread"}])

    def test_parses_grouped_products_payload(self) -> None:
        payload = {
            "productGroups": [
                {"products": [{"productId": "4", "name": "Cheese"}]},
                {"decoratedProducts": [{"productId": "5", "name": "Ham"}]},
            ]
        }
        parsed = _parse_products_payload(payload)
        self.assertEqual([item["productId"] for item in parsed], ["4", "5"])


if __name__ == "__main__":
    unittest.main()
