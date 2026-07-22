"""Data coordinator for Bonpreu integration."""

from __future__ import annotations

import asyncio
from datetime import timedelta
import logging
from typing import Any, Awaitable, Callable

from homeassistant.config_entries import ConfigEntry
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api.client import BonpreuApiClient
from .api.exceptions import BonpreuApiError, BonpreuAuthError
from .const import CONF_UPDATE_INTERVAL_MINUTES, DEFAULT_UPDATE_INTERVAL, DOMAIN

_LOGGER = logging.getLogger(__name__)

_ENDPOINT_DEFAULTS: dict[str, Any] = {
    "cart": {},
    "shopping_lists": [],
    "recent_orders": {},
    "orders_not_cancelled_count": {},
    "regulars": {},
}


class BonpreuDataUpdateCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinator for fetching Bonpreu data."""

    def __init__(self, hass, entry: ConfigEntry, client: BonpreuApiClient) -> None:
        update_interval = timedelta(
            minutes=entry.options.get(
                CONF_UPDATE_INTERVAL_MINUTES,
                int(DEFAULT_UPDATE_INTERVAL.total_seconds() / 60),
            )
        )
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=update_interval,
        )
        self._entry = entry
        self.client = client
        self._mutation_lock = asyncio.Lock()
        self._product_cache_by_product_id: dict[str, dict[str, Any]] = {}
        self._product_cache_by_retailer_id: dict[str, dict[str, Any]] = {}

    def _remember_product(self, product: dict[str, Any]) -> None:
        """Persist product payload in in-memory lookups."""
        product_id = str(product.get("productId") or "").strip()
        retailer_product_id = str(product.get("retailerProductId") or "").strip()
        if product_id:
            self._product_cache_by_product_id[product_id] = product
        if retailer_product_id:
            self._product_cache_by_retailer_id[retailer_product_id] = product

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from Bonpreu API."""
        previous = self.data or {}
        merged: dict[str, Any] = {**previous}
        endpoint_status: dict[str, str] = dict(previous.get("_endpoint_status") or {})
        endpoint_errors: dict[str, str] = {}
        success_count = 0

        for key, fetcher in self._endpoint_fetchers:
            try:
                merged[key] = await fetcher()
                endpoint_status[key] = "ok"
                success_count += 1
            except BonpreuAuthError as err:
                raise ConfigEntryAuthFailed("Bonpreu authentication failed.") from err
            except BonpreuApiError as err:
                reason = _error_reason(err)
                endpoint_status[key] = f"error:{reason}"
                endpoint_errors[key] = reason
                if key not in merged:
                    merged[key] = _ENDPOINT_DEFAULTS[key]
                _LOGGER.warning(
                    "Bonpreu endpoint '%s' refresh failed (%s); keeping previous data.",
                    key,
                    reason,
                )

        if success_count == 0 and not previous:
            raise UpdateFailed("Could not refresh any Bonpreu endpoint.")

        merged["_endpoint_status"] = endpoint_status
        merged["_endpoint_errors"] = endpoint_errors
        merged["_last_update_success_count"] = success_count
        return merged

    @property
    def _endpoint_fetchers(self) -> tuple[tuple[str, Callable[[], Awaitable[Any]]], ...]:
        return (
            ("cart", self._fetch_cart_with_products),
            ("shopping_lists", self.client.get_shopping_lists),
            ("recent_orders", self.client.get_orders_recent),
            ("orders_not_cancelled_count", self.client.get_orders_not_cancelled_count),
            ("regulars", lambda: self.client.get_regulars(limit=100, offset=0)),
        )

    async def _fetch_cart_with_products(self) -> dict[str, Any]:
        """Fetch cart and enrich item metadata with product details."""
        cart_payload = await self.client.get_cart_active()
        if isinstance(cart_payload, dict):
            try:
                cart_view = await self.client.get_cart_view()
            except BonpreuApiError as err:
                _LOGGER.debug("Cart view enrichment failed: %s", err)
            else:
                _merge_cart_view_items(cart_payload, cart_view)
            await self._enrich_cart_items(cart_payload)
        return cart_payload

    async def _enrich_cart_items(self, cart_payload: dict[str, Any]) -> None:
        """Populate cart items with product names and metadata when missing."""
        item_dicts = _extract_cart_item_dicts(cart_payload)
        if not item_dicts:
            return

        product_ids = _collect_product_ids(item_dicts)
        retailer_product_ids = _collect_retailer_product_ids(item_dicts)
        by_product_id: dict[str, dict[str, Any]] = dict(self._product_cache_by_product_id)
        by_retailer_id: dict[str, dict[str, Any]] = dict(self._product_cache_by_retailer_id)

        products: list[dict[str, Any]] = []
        if product_ids:
            try:
                products = await self.client.get_products(product_ids)
            except BonpreuApiError as err:
                _LOGGER.debug("Cart product enrichment failed: %s", err)
                if err.status_code == 422 and retailer_product_ids:
                    products = await self._fetch_products_by_retailer_id(retailer_product_ids)

        for product in products:
            if not isinstance(product, dict):
                continue
            product_id = str(product.get("productId") or "").strip()
            retailer_product_id = str(product.get("retailerProductId") or "").strip()
            if product_id:
                by_product_id[product_id] = product
            if retailer_product_id:
                by_retailer_id[retailer_product_id] = product
            self._remember_product(product)

        for item in item_dicts:
            product_id = str(item.get("productId") or "").strip()
            retailer_product_id = str(item.get("retailerProductId") or "").strip()

            product = None
            if product_id:
                product = by_product_id.get(product_id)
            if product is None and retailer_product_id:
                product = by_retailer_id.get(retailer_product_id)
            if product is None:
                continue

            name = _extract_best_product_name(product)
            if name:
                item.setdefault("name", name)
                item.setdefault("productName", name)

            brand = str(product.get("brand") or "").strip()
            if brand:
                item.setdefault("brand", brand)

            resolved_retailer_product_id = str(product.get("retailerProductId") or "").strip()
            if resolved_retailer_product_id and not item.get("retailerProductId"):
                item["retailerProductId"] = resolved_retailer_product_id

    async def _fetch_products_by_retailer_id(self, retailer_product_ids: list[str]) -> list[dict[str, Any]]:
        """Fallback enrichment using product detail endpoint per retailer id."""

        async def _fetch_one(retailer_product_id: str) -> dict[str, Any] | None:
            try:
                payload = await self.client.get_product_detail(retailer_product_id)
            except BonpreuApiError as err:
                _LOGGER.debug(
                    "Cart fallback enrichment failed for retailer product '%s': %s",
                    retailer_product_id,
                    err,
                )
                return None
            return _extract_product_from_detail_payload(payload, retailer_product_id)

        products = await asyncio.gather(*(_fetch_one(product_id) for product_id in retailer_product_ids))
        return [product for product in products if isinstance(product, dict)]

    async def async_search_catalog_products(
        self,
        *,
        query: str,
        max_page_size: int = 30,
        page_token: str | None = None,
        category_id: str | None = None,
        encoded_filters: str | None = None,
        sort_option_id: str | None = None,
        include_additional_page_info: bool = True,
    ) -> dict[str, Any]:
        """Search products and cache returned product metadata."""
        payload = await self.client.search_products(
            query=query,
            max_page_size=max_page_size,
            page_token=page_token,
            category_id=category_id,
            encoded_filters=encoded_filters,
            sort_option_id=sort_option_id,
            include_additional_page_info=include_additional_page_info,
        )
        for product in _extract_products_from_search_payload(payload):
            self._remember_product(product)
        self._set_endpoint_data("catalog_search", payload)
        return payload

    async def async_get_catalog_product_detail(self, retailer_product_id: str) -> dict[str, Any]:
        """Fetch product detail and cache returned product metadata."""
        payload = await self.client.get_product_detail(retailer_product_id)
        product = _extract_product_from_detail_payload(payload, retailer_product_id)
        if isinstance(product, dict):
            self._remember_product(product)
        self._set_endpoint_data("catalog_product_detail", payload)
        return payload

    def _set_endpoint_data(self, key: str, value: Any) -> None:
        """Update a single endpoint payload in coordinator cache."""
        merged: dict[str, Any] = dict(self.data or {})
        merged[key] = value

        endpoint_status: dict[str, str] = dict(merged.get("_endpoint_status") or {})
        endpoint_status[key] = "ok"
        merged["_endpoint_status"] = endpoint_status

        endpoint_errors: dict[str, str] = dict(merged.get("_endpoint_errors") or {})
        endpoint_errors.pop(key, None)
        merged["_endpoint_errors"] = endpoint_errors

        self.async_set_updated_data(merged)

    async def _refresh_cart_cache(self) -> dict[str, Any]:
        """Refresh only cart payload and update in-memory coordinator data."""
        cart_payload = await self._fetch_cart_with_products()
        self._set_endpoint_data("cart", cart_payload)
        return cart_payload

    async def async_add_to_cart(self, retailer_product_id: str, delta: int = 1) -> dict[str, Any]:
        """Service helper to add/remove items from basket."""
        async with self._mutation_lock:
            result = await self.client.add_to_cart(retailer_product_id, delta)
            await self._refresh_cart_cache()
        await self.async_request_refresh()
        return result

    async def async_set_cart_quantity(
        self,
        retailer_product_id: str,
        target_quantity: int,
    ) -> dict[str, Any]:
        """Service helper to set product quantity in active basket."""
        async with self._mutation_lock:
            cart_payload = await self._refresh_cart_cache()
            current_quantity = _cart_quantity_for_product(cart_payload, retailer_product_id)
            delta = target_quantity - current_quantity
            if delta == 0:
                return {
                    "changed": False,
                    "retailer_product_id": retailer_product_id,
                    "target_quantity": target_quantity,
                }

            result = await self.client.add_to_cart(retailer_product_id, delta)
            await self._refresh_cart_cache()

        await self.async_request_refresh()
        return {
            "changed": True,
            "retailer_product_id": retailer_product_id,
            "target_quantity": target_quantity,
            "delta": delta,
            "result": result,
        }

    async def async_add_shopping_list_to_cart(self, list_id: str) -> dict[str, Any]:
        """Service helper to move list into basket."""
        async with self._mutation_lock:
            result = await self.client.add_shopping_list_to_cart(list_id)
            await self._refresh_cart_cache()
        await self.async_request_refresh()
        return result

    async def async_create_shopping_list(self, list_name: str, products: list[str] | None = None) -> dict[str, Any]:
        """Service helper to create shopping list."""
        result = await self.client.create_shopping_list(list_name, products or [])
        await self.async_request_refresh()
        return result

    async def async_rename_shopping_list(self, list_id: str, list_name: str) -> None:
        """Service helper to rename shopping list."""
        await self.client.rename_shopping_list(list_id, list_name)
        await self.async_request_refresh()

    async def async_delete_shopping_list(self, list_id: str) -> None:
        """Service helper to delete shopping list."""
        await self.client.delete_shopping_list(list_id)
        await self.async_request_refresh()

    @staticmethod
    def parse_cart_total(data: dict[str, Any]) -> float | None:
        """Extract basket total in major currency units."""
        payload = data.get("cart")
        totals = _extract_totals(payload)
        if totals:
            amount = _extract_amount_by_keys(
                totals,
                (
                    "itemPriceAfterPromos",
                    "totalPriceAfterPromos",
                    "orderTotal",
                    "cartTotal",
                    "total",
                    "amount",
                ),
            )
            if amount is not None:
                return amount

        return _extract_amount_by_keys(
            payload,
            (
                "itemPriceAfterPromos",
                "totalPriceAfterPromos",
                "orderTotal",
                "cartTotal",
                "total",
                "amount",
            ),
        )

    @staticmethod
    def parse_cart_items_count(data: dict[str, Any]) -> int:
        """Extract basket product line count."""
        return len(_extract_cart_items(data.get("cart")))

    @staticmethod
    def parse_cart_units_count(data: dict[str, Any]) -> int:
        """Extract total quantity units from basket lines."""
        total_units = 0
        for item in _extract_cart_items(data.get("cart")):
            total_units += int(item.get("quantity") or 0)
        return total_units

    @staticmethod
    def parse_amount_to_free_delivery(data: dict[str, Any]) -> float | None:
        """Extract remaining amount to free delivery threshold when available."""
        payload = data.get("cart")
        totals = _extract_totals(payload)
        if totals:
            amount = _extract_amount_by_keys(
                totals,
                (
                    "amountToFreeDelivery",
                    "remainingForFreeDelivery",
                    "freeDeliveryRemaining",
                    "remainingForShippingPromotion",
                ),
            )
            if amount is not None:
                return amount

        return _extract_amount_by_keys(
            payload,
            (
                "amountToFreeDelivery",
                "remainingForFreeDelivery",
                "freeDeliveryRemaining",
                "remainingForShippingPromotion",
            ),
        )

    @staticmethod
    def parse_shopping_lists_count(data: dict[str, Any]) -> int:
        return len(_extract_shopping_lists(data.get("shopping_lists")))

    @staticmethod
    def parse_recent_orders_count(data: dict[str, Any]) -> int:
        return len(_extract_recent_orders(data.get("recent_orders")))

    @staticmethod
    def parse_orders_waiting_shipment_count(data: dict[str, Any]) -> int:
        return len(_extract_waiting_orders(_extract_recent_orders(data.get("recent_orders"))))

    @staticmethod
    def parse_orders_waiting_shipment_preview(data: dict[str, Any], *, limit: int = 10) -> list[dict[str, Any]]:
        orders = _extract_recent_orders(data.get("recent_orders"))
        return _extract_waiting_orders(orders)[:limit]

    @staticmethod
    def parse_active_orders_count(data: dict[str, Any]) -> int:
        return _extract_count_by_keys(
            data.get("orders_not_cancelled_count"),
            (
                "notCancelledCount",
                "notCanceledCount",
                "activeOrders",
                "activeOrdersCount",
                "count",
                "total",
                "totalCount",
            ),
        )

    @staticmethod
    def parse_regulars_count(data: dict[str, Any]) -> int:
        regulars = _extract_regular_products(data.get("regulars"))
        if regulars:
            return len(regulars)
        return _extract_count_by_keys(
            data.get("regulars"),
            (
                "total",
                "count",
                "totalCount",
                "itemCount",
                "productCount",
            ),
        )

    @staticmethod
    def parse_catalog_search_products_count(data: dict[str, Any]) -> int:
        payload = data.get("catalog_search")
        if not isinstance(payload, dict):
            return 0
        return len(_extract_products_from_search_payload(payload))

    @staticmethod
    def parse_cart_items_preview(data: dict[str, Any], *, limit: int = 15) -> list[dict[str, Any]]:
        return _extract_cart_items(data.get("cart"))[:limit]

    @staticmethod
    def parse_shopping_lists_preview(data: dict[str, Any], *, limit: int = 15) -> list[dict[str, Any]]:
        return _extract_shopping_lists(data.get("shopping_lists"))[:limit]

    @staticmethod
    def parse_recent_orders_preview(data: dict[str, Any], *, limit: int = 10) -> list[dict[str, Any]]:
        return _extract_recent_orders(data.get("recent_orders"))[:limit]

    @staticmethod
    def parse_regulars_preview(data: dict[str, Any], *, limit: int = 20) -> list[dict[str, Any]]:
        return _extract_regular_products(data.get("regulars"))[:limit]


def _error_reason(err: BonpreuApiError) -> str:
    if err.status_code is not None:
        return f"http_{err.status_code}"
    return "request_error"


def _extract_cart_item_dicts(cart_payload: Any) -> list[dict[str, Any]]:
    cart = _extract_cart_root(cart_payload)
    raw_items = _extract_first_list(
        cart,
        (
            "items",
            "lines",
            "products",
            "cartItems",
            "basketItems",
        ),
    )
    if not raw_items:
        return []
    return [item for item in raw_items if isinstance(item, dict)]


def _merge_cart_view_items(cart_payload: dict[str, Any], cart_view: Any) -> None:
    """Copy product metadata from the detailed cart-view response into cart lines."""
    view_products = _collect_cart_view_products(cart_view)
    if not view_products:
        return

    for item in _extract_cart_item_dicts(cart_payload):
        product = _match_product_metadata(item, view_products)
        if product is None:
            continue

        name = _extract_best_product_name(product)
        if name:
            item.setdefault("name", name)
            item.setdefault("productName", name)

        for source_key, target_key in (
            ("brand", "brand"),
            ("description", "description"),
            ("available", "available"),
            ("isAvailable", "isAvailable"),
            ("retailerProductId", "retailerProductId"),
            ("productId", "productId"),
        ):
            if target_key not in item and source_key in product:
                item[target_key] = product[source_key]


def _collect_cart_view_products(payload: Any) -> list[dict[str, Any]]:
    """Find named product-like objects in the nested cart-view response."""
    products: list[dict[str, Any]] = []
    seen: set[int] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            value_id = id(value)
            if value_id in seen:
                return
            seen.add(value_id)

            has_identifier = any(
                _stringify_identifier(value.get(key))
                for key in ("productId", "retailerProductId", "id", "sku")
            )
            has_name = _extract_best_product_name(value) is not None
            if has_identifier and has_name:
                products.append(value)

            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(payload)
    return products


def _match_product_metadata(
    item: dict[str, Any],
    products: list[dict[str, Any]],
) -> dict[str, Any] | None:
    item_ids = {
        _stringify_identifier(item.get(key)).lower()
        for key in ("productId", "retailerProductId", "id", "sku")
        if _stringify_identifier(item.get(key))
    }
    if not item_ids:
        return None

    for product in products:
        product_ids = {
            _stringify_identifier(product.get(key)).lower()
            for key in ("productId", "retailerProductId", "id", "sku")
            if _stringify_identifier(product.get(key))
        }
        if item_ids & product_ids:
            return product
    return None


def _collect_product_ids(items: list[dict[str, Any]]) -> list[str]:
    unique_ids: dict[str, None] = {}
    for item in items:
        primary_candidates = (_stringify_identifier(item.get("productId")), _stringify_identifier(item.get("id")))
        chosen = next((candidate for candidate in primary_candidates if candidate), "")
        if not chosen:
            chosen = _stringify_identifier(item.get("retailerProductId"))
        if chosen:
            unique_ids[chosen] = None
    return list(unique_ids)


def _collect_retailer_product_ids(items: list[dict[str, Any]]) -> list[str]:
    unique_ids: dict[str, None] = {}
    for item in items:
        retailer_product_id = _stringify_identifier(item.get("retailerProductId"))
        if not retailer_product_id:
            retailer_product_id = _stringify_identifier(item.get("retailer_product_id"))
        if retailer_product_id:
            unique_ids[retailer_product_id] = None
    return list(unique_ids)


def _stringify_identifier(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(int(value)) if isinstance(value, float) else str(value)
    return ""


def _extract_best_product_name(product: dict[str, Any]) -> str | None:
    for key in ("name", "productName", "title", "description"):
        value = product.get(key)
        if isinstance(value, str):
            cleaned = value.strip()
            if cleaned:
                return cleaned
    return None


def _extract_product_from_detail_payload(payload: Any, retailer_product_id: str) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None

    product = payload.get("product")
    if not isinstance(product, dict):
        product = payload
    if not isinstance(product, dict):
        return None

    normalized = dict(product)
    if not _stringify_identifier(normalized.get("retailerProductId")) and retailer_product_id:
        normalized["retailerProductId"] = retailer_product_id

    has_identifier = any(
        _stringify_identifier(normalized.get(key))
        for key in ("productId", "retailerProductId", "id", "sku")
    )
    if not has_identifier:
        return None
    return normalized


def _extract_products_from_search_payload(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []

    products: list[dict[str, Any]] = []

    groups = payload.get("productGroups")
    if isinstance(groups, list):
        for group in groups:
            if not isinstance(group, dict):
                continue
            for key in ("products", "decoratedProducts"):
                values = group.get(key)
                if not isinstance(values, list):
                    continue
                for item in values:
                    if isinstance(item, dict):
                        products.append(_unwrap_nested_product(item))
        if products:
            return products

    for key in ("products", "items", "data", "content"):
        values = payload.get(key)
        if not isinstance(values, list):
            continue
        return [_unwrap_nested_product(item) for item in values if isinstance(item, dict)]

    return []


def _unwrap_nested_product(product: dict[str, Any]) -> dict[str, Any]:
    nested = product.get("product")
    if not isinstance(nested, dict):
        return product

    merged = dict(nested)
    for key in ("productId", "retailerProductId", "id", "sku"):
        if merged.get(key):
            continue
        value = product.get(key)
        if value is not None:
            merged[key] = value
    return merged


def _cart_quantity_for_product(cart_payload: Any, retailer_product_id: str) -> int:
    wanted = retailer_product_id.strip().lower()
    if not wanted:
        return 0

    for item in _extract_cart_items(cart_payload):
        candidate = str(item.get("retailer_product_id") or "").strip().lower()
        if candidate == wanted:
            return int(item.get("quantity") or 0)
    return 0


def _extract_totals(payload: Any) -> dict[str, Any] | None:
    if isinstance(payload, dict):
        totals = payload.get("totals")
        if isinstance(totals, dict):
            return totals
    return _extract_first_mapping(payload, ("itemPriceAfterPromos", "total", "cartTotal", "orderTotal"))


def _extract_cart_items(payload: Any) -> list[dict[str, Any]]:
    cart = _extract_cart_root(payload)
    raw_items = _extract_first_list(
        cart,
        (
            "items",
            "lines",
            "products",
            "cartItems",
            "basketItems",
        ),
    )

    if raw_items is None:
        return []

    items: list[dict[str, Any]] = []
    for index, raw_item in enumerate(raw_items):
        if not isinstance(raw_item, dict):
            continue

        retailer_product_id = _extract_first_str(
            raw_item,
            (
                "retailerProductId",
                "productId",
                "id",
                "sku",
                "ean",
            ),
        )
        name = _extract_first_str(
            raw_item,
            (
                "productName",
                "name",
                "title",
                "description",
            ),
        )
        quantity = _extract_quantity(raw_item)
        unit_price = _extract_amount_by_keys(raw_item, ("unitPrice", "pricePerUnit", "price"))
        line_total = _extract_amount_by_keys(
            raw_item,
            (
                "itemPriceAfterPromos",
                "lineTotal",
                "totalPrice",
                "finalPrice",
            ),
        )

        if line_total is None and unit_price is not None:
            line_total = unit_price * quantity
        if unit_price is None and line_total is not None and quantity > 0:
            unit_price = line_total / quantity

        item: dict[str, Any] = {
            "retailer_product_id": retailer_product_id or f"line_{index}",
            "name": name or retailer_product_id or f"Product {index + 1}",
            "quantity": quantity,
        }
        if unit_price is not None:
            item["unit_price"] = round(unit_price, 2)
        if line_total is not None:
            item["line_total"] = round(line_total, 2)

        available = _extract_first_bool(raw_item, ("isAvailable", "available", "outOfStock"))
        if available is not None:
            item["available"] = not available if "outOfStock" in raw_item else available

        items.append(item)

    return items


def _extract_shopping_lists(payload: Any) -> list[dict[str, Any]]:
    raw_lists = _extract_first_list(
        payload,
        (
            "productLists",
            "shoppingLists",
            "lists",
            "items",
            "content",
            "data",
        ),
    )
    if raw_lists is None:
        return []

    lists: list[dict[str, Any]] = []
    for index, raw_list in enumerate(raw_lists):
        if not isinstance(raw_list, dict):
            continue
        list_id = _extract_first_str(raw_list, ("id", "listId", "productListId"))
        name = _extract_first_str(raw_list, ("listName", "name", "title"))
        product_count = _extract_count_by_keys(raw_list, ("productCount", "itemCount", "count", "total"))
        if product_count == 0:
            products = _extract_first_list(raw_list, ("products", "items", "productIds"))
            if isinstance(products, list):
                product_count = len(products)

        lists.append(
            {
                "list_id": list_id or f"list_{index}",
                "name": name or f"List {index + 1}",
                "product_count": product_count,
            }
        )

    return lists


def _extract_recent_orders(payload: Any) -> list[dict[str, Any]]:
    raw_orders = _extract_first_list(
        payload,
        (
            "orders",
            "recentOrders",
            "items",
            "content",
            "data",
        ),
    )
    if raw_orders is None:
        return []

    orders: list[dict[str, Any]] = []
    for index, raw_order in enumerate(raw_orders):
        if not isinstance(raw_order, dict):
            continue

        order_id = _extract_first_str(raw_order, ("orderId", "id", "number", "reference"))
        status = _extract_first_str(raw_order, ("status", "orderStatus", "state"))
        created_at = _extract_first_str(raw_order, ("createdAt", "creationDate", "date", "orderDate"))
        total = _extract_amount_by_keys(raw_order, ("total", "totalPrice", "amount", "orderTotal"))
        line_items = _extract_order_line_items(raw_order)
        item_count = _extract_count_by_keys(
            raw_order,
            ("itemCount", "itemsCount", "productCount", "lineCount", "totalItems"),
        )
        if item_count == 0 and line_items:
            item_count = len(line_items)

        order: dict[str, Any] = {
            "order_id": order_id or f"order_{index}",
        }
        if status:
            order["status"] = status
        if created_at:
            order["created_at"] = created_at
        if total is not None:
            order["total"] = round(total, 2)
        if item_count:
            order["item_count"] = item_count
        if line_items:
            order["items_preview"] = line_items[:8]
        order["waiting_shipment"] = _is_waiting_shipment_status(status)
        orders.append(order)

    return orders


def _extract_waiting_orders(orders: list[dict[str, Any]]) -> list[dict[str, Any]]:
    waiting: list[dict[str, Any]] = []
    for order in orders:
        status = order.get("status")
        if isinstance(status, str):
            if _is_waiting_shipment_status(status):
                waiting.append(order)
            continue

        if order.get("waiting_shipment"):
            waiting.append(order)
    return waiting


def _extract_regular_products(payload: Any) -> list[dict[str, Any]]:
    raw_regulars = _extract_first_list(
        payload,
        (
            "regulars",
            "products",
            "items",
            "content",
            "data",
        ),
    )
    if raw_regulars is None:
        return []

    products: list[dict[str, Any]] = []
    for index, raw_product in enumerate(raw_regulars):
        if not isinstance(raw_product, dict):
            continue

        retailer_product_id = _extract_first_str(
            raw_product,
            ("retailerProductId", "productId", "id", "sku", "ean"),
        )
        name = _extract_first_str(raw_product, ("name", "productName", "title", "description"))
        price = _extract_amount_by_keys(raw_product, ("price", "unitPrice", "finalPrice", "amount"))

        product: dict[str, Any] = {
            "retailer_product_id": retailer_product_id or f"regular_{index}",
            "name": name or retailer_product_id or f"Regular product {index + 1}",
        }
        if price is not None:
            product["price"] = round(price, 2)
        products.append(product)

    return products


def _extract_order_line_items(order_payload: Any) -> list[str]:
    raw_items = _extract_first_list(
        order_payload,
        (
            "items",
            "products",
            "lines",
            "orderItems",
        ),
    )
    if not raw_items:
        return []

    names: list[str] = []
    for raw_item in raw_items:
        if not isinstance(raw_item, dict):
            continue
        name = _extract_first_str(raw_item, ("name", "productName", "title", "description"))
        if name:
            names.append(name)
    return names


def _is_waiting_shipment_status(status: str | None) -> bool:
    if not status:
        return False

    lowered = status.lower()
    non_waiting_keywords = (
        "deliver",
        "entreg",
        "completed",
        "complet",
        "cancel",
        "cancell",
        "anulad",
        "rejected",
        "returned",
    )
    if any(keyword in lowered for keyword in non_waiting_keywords):
        return False

    waiting_keywords = (
        "pending",
        "paid",
        "prepar",
        "ready",
        "shipping",
        "shipment",
        "dispatch",
        "envi",
        "processing",
        "accepted",
        "confirmed",
    )
    return any(keyword in lowered for keyword in waiting_keywords)


def _extract_cart_root(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        if any(key in payload for key in ("items", "lines", "products", "totals")):
            return payload
        for key in ("cart", "activeCart", "basket", "data", "result"):
            nested = payload.get(key)
            if isinstance(nested, (dict, list)):
                found = _extract_cart_root(nested)
                if found:
                    return found
        for value in payload.values():
            if isinstance(value, (dict, list)):
                found = _extract_cart_root(value)
                if found:
                    return found
    elif isinstance(payload, list):
        for value in payload:
            if isinstance(value, (dict, list)):
                found = _extract_cart_root(value)
                if found:
                    return found
    return {}


def _extract_first_list(
    payload: Any,
    candidate_keys: tuple[str, ...],
    *,
    _accept_plain_list: bool = True,
) -> list[Any] | None:
    if isinstance(payload, list):
        if _accept_plain_list:
            return payload

        for value in payload:
            if isinstance(value, (dict, list)):
                found = _extract_first_list(
                    value,
                    candidate_keys,
                    _accept_plain_list=False,
                )
                if found is not None:
                    return found
        return None

    if isinstance(payload, dict):
        for key in candidate_keys:
            value = payload.get(key)
            if isinstance(value, list):
                return value
        for value in payload.values():
            if isinstance(value, (dict, list)):
                found = _extract_first_list(
                    value,
                    candidate_keys,
                    _accept_plain_list=False,
                )
                if found is not None:
                    return found

    return None


def _extract_first_mapping(payload: Any, candidate_keys: tuple[str, ...]) -> dict[str, Any] | None:
    if isinstance(payload, dict):
        if any(key in payload for key in candidate_keys):
            return payload
        for value in payload.values():
            if isinstance(value, (dict, list)):
                found = _extract_first_mapping(value, candidate_keys)
                if found is not None:
                    return found
    elif isinstance(payload, list):
        for value in payload:
            if isinstance(value, (dict, list)):
                found = _extract_first_mapping(value, candidate_keys)
                if found is not None:
                    return found
    return None


def _extract_count_by_keys(payload: Any, candidate_keys: tuple[str, ...]) -> int:
    if payload is None:
        return 0

    for key in candidate_keys:
        value = _find_first_key(payload, key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        if isinstance(value, float):
            return int(value)

    if isinstance(payload, list):
        return len(payload)

    return 0


def _extract_quantity(payload: dict[str, Any]) -> int:
    for key in ("quantity", "qty", "units", "amount", "count"):
        value = payload.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return max(0, value)
        if isinstance(value, float):
            return max(0, int(value))
        if isinstance(value, str):
            cleaned = value.strip().replace(",", ".")
            try:
                return max(0, int(float(cleaned)))
            except ValueError:
                continue
    return 1


def _extract_amount_by_keys(payload: Any, candidate_keys: tuple[str, ...]) -> float | None:
    if payload is None:
        return None

    for key in candidate_keys:
        value = _find_first_key(payload, key)
        amount = _extract_amount(value)
        if amount is not None:
            return amount

    return None


def _find_first_key(payload: Any, target_key: str) -> Any | None:
    if isinstance(payload, dict):
        if target_key in payload:
            return payload[target_key]
        for value in payload.values():
            if isinstance(value, (dict, list)):
                found = _find_first_key(value, target_key)
                if found is not None:
                    return found
    elif isinstance(payload, list):
        for value in payload:
            if isinstance(value, (dict, list)):
                found = _find_first_key(value, target_key)
                if found is not None:
                    return found
    return None


def _extract_first_str(payload: Any, candidate_keys: tuple[str, ...]) -> str | None:
    for key in candidate_keys:
        value = _find_first_key(payload, key)
        if isinstance(value, str):
            cleaned = value.strip()
            if cleaned:
                return cleaned
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
    return None


def _extract_first_bool(payload: Any, candidate_keys: tuple[str, ...]) -> bool | None:
    for key in candidate_keys:
        value = _find_first_key(payload, key)
        if isinstance(value, bool):
            return value
    return None


def _extract_amount(value: Any) -> float | None:
    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        return float(value)

    if isinstance(value, dict):
        for key in ("amount", "value", "majorUnits"):
            if key in value:
                inner = _extract_amount(value[key])
                if inner is not None:
                    return inner

        if "minorUnits" in value:
            minor = value.get("minorUnits")
            if isinstance(minor, (int, float)) and not isinstance(minor, bool):
                return float(minor) / 100.0
            if isinstance(minor, str):
                try:
                    return float(minor.strip()) / 100.0
                except ValueError:
                    pass

    if isinstance(value, str):
        cleaned = value.strip().replace(" ", "")
        if not cleaned:
            return None

        if "," in cleaned and "." in cleaned:
            cleaned = cleaned.replace(".", "").replace(",", ".")
        else:
            cleaned = cleaned.replace(",", ".")

        try:
            return float(cleaned)
        except ValueError:
            return None

    return None
