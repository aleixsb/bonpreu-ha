"""Tests for product payload parsing in API client."""

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

from custom_components.bonpreu.api.client import (
    BonpreuApiClient,
    _parse_products_payload,
    normalize_api_language,
)
from custom_components.bonpreu.api.exceptions import BonpreuApiError


class _FakeBonpreuApiClient(BonpreuApiClient):
    def __init__(self, *, outcomes: list[Any]) -> None:
        super().__init__(session=object(), language="ca-ES")
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

    def test_parses_grouped_products_with_nested_product(self) -> None:
        payload = {
            "productGroups": [
                {
                    "products": [
                        {
                            "productId": "outer-1",
                            "retailerProductId": "rp-1",
                            "product": {
                                "productId": "inner-1",
                                "name": "Coffee",
                            },
                        }
                    ]
                }
            ]
        }
        parsed = _parse_products_payload(payload)
        self.assertEqual(parsed[0]["productId"], "inner-1")
        self.assertEqual(parsed[0]["retailerProductId"], "rp-1")
        self.assertEqual(parsed[0]["name"], "Coffee")


class ApiClientCatalogMethodsTests(unittest.TestCase):
    def test_search_products_preserves_encoded_filters(self) -> None:
        client = _FakeBonpreuApiClient(outcomes=[{"productGroups": []}])

        payload = asyncio.run(
            client.search_products(
                query="llet entera",
                screen_size="S",
                max_products_to_decorate=100,
                max_page_size=30,
                include_additional_page_info=True,
                encoded_filters="offer%3Atrue",
                category_id="cat-1",
                page_token="next token",
            )
        )

        self.assertEqual(payload, {"productGroups": []})
        self.assertEqual(client.calls[0]["method"], "GET")
        path = str(client.calls[0]["path"])
        self.assertIn("q=llet%20entera", path)
        self.assertIn("filters=offer%3Atrue", path)
        self.assertIn("categoryId=cat-1", path)
        self.assertIn("pageToken=next%20token", path)

    def test_search_products_requires_dict_response(self) -> None:
        client = _FakeBonpreuApiClient(outcomes=[["invalid"]])
        with self.assertRaises(BonpreuApiError):
            asyncio.run(client.search_products(query="llet"))

    def test_get_product_detail_encodes_retailer_product_id(self) -> None:
        client = _FakeBonpreuApiClient(outcomes=[{"product": {"productId": "p-1"}}])
        payload = asyncio.run(client.get_product_detail("abc/123"))
        self.assertEqual(payload, {"product": {"productId": "p-1"}})
        self.assertEqual(client.calls[0]["path"], "v2/products/abc%2F123/bop")

    def test_get_product_detail_requires_dict_response(self) -> None:
        client = _FakeBonpreuApiClient(outcomes=["invalid"])
        with self.assertRaises(BonpreuApiError):
            asyncio.run(client.get_product_detail("123"))


class NormalizeApiLanguageTests(unittest.TestCase):
    def test_catalan_languages_map_to_ca_es(self) -> None:
        self.assertEqual(normalize_api_language("ca"), "ca-ES")
        self.assertEqual(normalize_api_language("ca_ES"), "ca-ES")

    def test_spanish_languages_map_to_es_es(self) -> None:
        self.assertEqual(normalize_api_language("es"), "es-ES")
        self.assertEqual(normalize_api_language("es-MX"), "es-ES")

    def test_unsupported_languages_fallback_to_ca_es(self) -> None:
        self.assertEqual(normalize_api_language("en"), "ca-ES")
        self.assertEqual(normalize_api_language(None), "ca-ES")


if __name__ == "__main__":
    unittest.main()
