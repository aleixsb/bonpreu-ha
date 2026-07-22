"""Tests for cart enrichment and mutation behavior."""

from __future__ import annotations

import sys
import types
import unittest
from types import SimpleNamespace
from typing import Any


def _install_homeassistant_stubs() -> None:
    homeassistant = types.ModuleType("homeassistant")
    homeassistant.__path__ = []
    config_entries = types.ModuleType("homeassistant.config_entries")
    const = types.ModuleType("homeassistant.const")
    core = types.ModuleType("homeassistant.core")
    exceptions = types.ModuleType("homeassistant.exceptions")
    helpers = types.ModuleType("homeassistant.helpers")
    aiohttp_client = types.ModuleType("homeassistant.helpers.aiohttp_client")
    update_coordinator = types.ModuleType("homeassistant.helpers.update_coordinator")

    class ConfigEntry:
        def __init__(self, options: dict[str, Any] | None = None) -> None:
            self.options = options or {}

    class ConfigEntryAuthFailed(Exception):
        pass

    class Platform:
        SENSOR = "sensor"
        TODO = "todo"

    class HomeAssistant:
        pass

    class UpdateFailed(Exception):
        pass

    class DataUpdateCoordinator:
        def __class_getitem__(cls, item):
            del item
            return cls

        def __init__(self, hass, logger, *, name, update_interval) -> None:
            self.hass = hass
            self.logger = logger
            self.name = name
            self.update_interval = update_interval
            self.data = None

        async def async_request_refresh(self) -> None:
            return None

        def async_set_updated_data(self, data) -> None:
            self.data = data

    config_entries.ConfigEntry = ConfigEntry
    const.CONF_LANGUAGE = "language"
    const.Platform = Platform
    core.HomeAssistant = HomeAssistant
    exceptions.ConfigEntryAuthFailed = ConfigEntryAuthFailed
    aiohttp_client.async_get_clientsession = lambda hass: None
    update_coordinator.DataUpdateCoordinator = DataUpdateCoordinator
    update_coordinator.UpdateFailed = UpdateFailed

    sys.modules["homeassistant"] = homeassistant
    sys.modules["homeassistant.config_entries"] = config_entries
    sys.modules["homeassistant.const"] = const
    sys.modules["homeassistant.core"] = core
    sys.modules["homeassistant.exceptions"] = exceptions
    sys.modules["homeassistant.helpers"] = helpers
    sys.modules["homeassistant.helpers.aiohttp_client"] = aiohttp_client
    sys.modules["homeassistant.helpers.update_coordinator"] = update_coordinator


def _install_aiohttp_stubs() -> None:
    if "aiohttp" in sys.modules:
        aiohttp = sys.modules["aiohttp"]
    else:
        aiohttp = types.ModuleType("aiohttp")

    class ClientError(Exception):
        pass

    class ClientTimeout:
        def __init__(self, total: float | None = None) -> None:
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

from custom_components.bonpreu.api.exceptions import BonpreuApiError
from custom_components.bonpreu.coordinator import BonpreuDataUpdateCoordinator


class _FakeClient:
    def __init__(self) -> None:
        self.cart_payload: dict[str, Any] = {"items": []}
        self.products_payload: list[dict[str, Any]] = []
        self.raise_products_error = False
        self.add_calls: list[tuple[str, int]] = []
        self.get_cart_calls = 0

        self.cart_view_payload: dict[str, Any] = {}

    async def get_cart_active(self) -> dict[str, Any]:
        self.get_cart_calls += 1
        return self.cart_payload

    async def get_products(self, product_ids: list[str]) -> list[dict[str, Any]]:
        if self.raise_products_error:
            raise BonpreuApiError("enrichment failed")
        return self.products_payload

    async def get_cart_view(self) -> dict[str, Any]:
        return self.cart_view_payload

    async def add_to_cart(self, retailer_product_id: str, delta: int = 1) -> dict[str, Any]:
        self.add_calls.append((retailer_product_id, delta))
        return {"ok": True}

    async def get_shopping_lists(self) -> list[Any]:
        return []

    async def get_orders_recent(self) -> dict[str, Any]:
        return {}

    async def get_orders_not_cancelled_count(self) -> dict[str, Any]:
        return {}

    async def get_regulars(self, *, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        del limit, offset
        return {}

    async def add_shopping_list_to_cart(self, list_id: str) -> dict[str, Any]:
        del list_id
        return {"ok": True}


class CoordinatorCartTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.client = _FakeClient()
        entry = SimpleNamespace(options={})
        self.coordinator = BonpreuDataUpdateCoordinator(object(), entry, self.client)

    async def test_cart_enrichment_populates_item_name(self) -> None:
        self.client.cart_payload = {
            "items": [
                {
                    "productId": "uuid-1",
                    "retailerProductId": "12345",
                    "quantity": 1,
                }
            ]
        }
        self.client.products_payload = [
            {
                "productId": "uuid-1",
                "retailerProductId": "12345",
                "name": "Whole Milk",
                "brand": "Bonpreu",
            }
        ]

        payload = await self.coordinator._fetch_cart_with_products()
        item = payload["items"][0]

        self.assertEqual(item.get("name"), "Whole Milk")
        self.assertEqual(item.get("productName"), "Whole Milk")
        self.assertEqual(item.get("brand"), "Bonpreu")

    async def test_cart_enrichment_uses_cache_when_api_temporarily_fails(self) -> None:
        self.client.cart_payload = {
            "items": [
                {
                    "productId": "uuid-2",
                    "retailerProductId": "67890",
                    "quantity": 1,
                }
            ]
        }
        self.client.products_payload = [
            {
                "productId": "uuid-2",
                "retailerProductId": "67890",
                "name": "Greek Yogurt",
            }
        ]
        await self.coordinator._fetch_cart_with_products()

        self.client.raise_products_error = True
        self.client.cart_payload = {
            "items": [
                {
                    "productId": "uuid-2",
                    "retailerProductId": "67890",
                    "quantity": 2,
                }
            ]
        }

        payload = await self.coordinator._fetch_cart_with_products()
        self.assertEqual(payload["items"][0].get("name"), "Greek Yogurt")

    async def test_cart_view_enrichment_populates_nested_product_name(self) -> None:
        self.client.cart_payload = {
            "items": [
                {
                    "productId": "product-3",
                    "retailerProductId": "14104",
                    "quantity": 1,
                }
            ]
        }
        self.client.cart_view_payload = {
            "checkoutGroups": [
                {
                    "unassignedProducts": [
                        {
                            "productId": "product-3",
                            "retailerProductId": "14104",
                            "description": "Fresh Orange Juice",
                            "available": True,
                        }
                    ]
                }
            ]
        }

        payload = await self.coordinator._fetch_cart_with_products()
        item = payload["items"][0]

        self.assertEqual(item.get("name"), "Fresh Orange Juice")
        self.assertEqual(item.get("productName"), "Fresh Orange Juice")

    async def test_set_cart_quantity_uses_fresh_server_cart_before_delta(self) -> None:
        self.coordinator.data = {
            "cart": {
                "items": [
                    {
                        "retailerProductId": "12345",
                        "quantity": 11,
                    }
                ]
            }
        }
        self.client.cart_payload = {
            "items": [
                {
                    "retailerProductId": "12345",
                    "quantity": 3,
                }
            ]
        }

        result = await self.coordinator.async_set_cart_quantity("12345", target_quantity=1)

        self.assertTrue(result["changed"])
        self.assertEqual(result["delta"], -2)
        self.assertEqual(self.client.add_calls, [("12345", -2)])
        self.assertGreaterEqual(self.client.get_cart_calls, 2)


if __name__ == "__main__":
    unittest.main()
