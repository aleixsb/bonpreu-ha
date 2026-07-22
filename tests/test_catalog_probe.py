"""Unit tests for local catalog probe helpers."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tools.bonpreu_auth_probe import ApiError, MobileApiClient, TokenPair
from tools.bonpreu_catalog_probe import (
    LocalSession,
    _extract_products_from_search_payload,
    _normalize_product,
    _request_with_session_refresh,
    load_local_session,
    save_local_session,
)


class _FakeMobileApiClient(MobileApiClient):
    def __init__(self) -> None:
        super().__init__(language="ca-ES")
        self.calls: list[dict[str, object]] = []
        self.outcomes: list[object] = []

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, object] | None = None,
        form_body: dict[str, str] | None = None,
    ) -> object:
        self.calls.append(
            {
                "method": method,
                "path": path,
                "headers": headers or {},
                "json_body": json_body,
                "form_body": form_body,
            }
        )
        if not self.outcomes:
            return {}
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class CatalogProbeTests(unittest.TestCase):
    def test_session_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            session = LocalSession(
                schema_version=1,
                device_id="device-1",
                device_token="device-token",
                access_token="access-token",
                refresh_token="refresh-token",
                language="ca-ES",
                created_at="2026-01-01T00:00:00+00:00",
                updated_at="2026-01-01T00:00:00+00:00",
                last_verified_at=None,
            )
            save_local_session(home, session)
            loaded = load_local_session(home)
            self.assertEqual(loaded, session)

    def test_load_session_missing_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            self.assertIsNone(load_local_session(home))

    def test_extract_products_from_search_payload(self) -> None:
        payload = {
            "productGroups": [
                {"products": [{"productId": "p1"}]},
                {"decoratedProducts": [{"productId": "p2"}]},
            ]
        }
        products = _extract_products_from_search_payload(payload)
        self.assertEqual([item["productId"] for item in products], ["p1", "p2"])

    def test_normalize_product(self) -> None:
        product = {
            "productId": "pid-1",
            "retailerProductId": "12345",
            "description": "Milk",
            "brand": "BONPREU",
            "size": "1L",
            "available": True,
            "maxAvailableQuantity": 6,
            "price": {
                "raw": {"amount": "1.59"},
                "unit": {"amount": "1.59", "format": "EUR/L"},
            },
            "promotions": [{"id": "promo1"}],
            "categoryPath": [{"name": "Dairy"}],
        }
        normalized = _normalize_product(product)
        self.assertEqual(normalized["retailer_product_id"], "12345")
        self.assertEqual(normalized["name"], "Milk")
        self.assertEqual(normalized["price"], "1.59")
        self.assertEqual(normalized["unit_price"], "1.59")
        self.assertEqual(normalized["unit"], "EUR/L")
        self.assertEqual(normalized["promotion_count"], 1)
        self.assertEqual(normalized["categories"], ["Dairy"])

    def test_normalize_product_nested_product_payload(self) -> None:
        product = {
            "productId": "outer-id",
            "product": {
                "productId": "inner-id",
                "retailerProductId": "7788",
                "description": "Coffee",
                "brand": "BONPREU",
                "available": True,
                "price": {
                    "raw": {"amount": "2.99"},
                    "unit": {"amount": "2.99", "format": "EUR/u"},
                },
                "promotions": [],
            },
        }
        normalized = _normalize_product(product)
        self.assertEqual(normalized["product_id"], "inner-id")
        self.assertEqual(normalized["retailer_product_id"], "7788")
        self.assertEqual(normalized["name"], "Coffee")
        self.assertEqual(normalized["price"], "2.99")

    def test_request_with_session_refresh(self) -> None:
        api = _FakeMobileApiClient()
        session = LocalSession(
            schema_version=1,
            device_id="device-1",
            device_token="device-token",
            access_token="old-access",
            refresh_token="old-refresh",
            language="ca-ES",
            created_at="2026-01-01T00:00:00+00:00",
            updated_at="2026-01-01T00:00:00+00:00",
            last_verified_at=None,
        )

        attempts = {"count": 0}

        def request_fn(access_token: str) -> str:
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise ApiError("unauthorized", status_code=401)
            return f"ok:{access_token}"

        api.outcomes = [{"token": "new-access", "refreshToken": "new-refresh"}]
        response, updated = _request_with_session_refresh(api=api, session=session, request_fn=request_fn)

        self.assertEqual(response, "ok:new-access")
        self.assertEqual(updated.access_token, "new-access")
        self.assertEqual(updated.refresh_token, "new-refresh")
        self.assertEqual(attempts["count"], 2)

    def test_search_products_preserves_encoded_filters(self) -> None:
        api = _FakeMobileApiClient()
        api.search_products(
            access_token="token-1",
            query="llet entera",
            screen_size="S",
            max_products_to_decorate=100,
            max_page_size=30,
            include_additional_page_info=True,
            encoded_filters="offer%3Atrue",
            category_id="cat-1",
            page_token="next token",
        )
        self.assertEqual(api.calls[0]["method"], "GET")
        path = str(api.calls[0]["path"])
        self.assertIn("q=llet%20entera", path)
        self.assertIn("filters=offer%3Atrue", path)
        self.assertIn("categoryId=cat-1", path)
        self.assertIn("pageToken=next%20token", path)

    def test_product_detail_encodes_retailer_product_id(self) -> None:
        api = _FakeMobileApiClient()
        api.get_product_detail(access_token="token-1", retailer_product_id="abc/123")
        self.assertEqual(api.calls[0]["path"], "v2/products/abc%2F123/bop")


if __name__ == "__main__":
    unittest.main()
