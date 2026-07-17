"""Diagnostics support for Bonpreu."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.redact import redact_data

from .const import (
    CONF_ACCESS_TOKEN,
    CONF_DEVICE_ID,
    CONF_DEVICE_TOKEN,
    CONF_REFRESH_TOKEN,
    DOMAIN,
)
from .coordinator import BonpreuDataUpdateCoordinator
from .runtime import BonpreuRuntimeData

TO_REDACT = {CONF_ACCESS_TOKEN, CONF_REFRESH_TOKEN, CONF_DEVICE_TOKEN, CONF_DEVICE_ID}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,
    entry: ConfigEntry,
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    runtime: BonpreuRuntimeData = hass.data[DOMAIN][entry.entry_id]
    data = runtime.coordinator.data or {}
    endpoint_status = data.get("_endpoint_status") or {}

    summary = {
        "cart_total": BonpreuDataUpdateCoordinator.parse_cart_total(data),
        "cart_product_lines": BonpreuDataUpdateCoordinator.parse_cart_items_count(data),
        "cart_units": BonpreuDataUpdateCoordinator.parse_cart_units_count(data),
        "shopping_lists_count": BonpreuDataUpdateCoordinator.parse_shopping_lists_count(data),
        "recent_orders_count": BonpreuDataUpdateCoordinator.parse_recent_orders_count(data),
        "orders_waiting_shipment_count": BonpreuDataUpdateCoordinator.parse_orders_waiting_shipment_count(data),
        "active_orders_count": BonpreuDataUpdateCoordinator.parse_active_orders_count(data),
        "regular_products_count": BonpreuDataUpdateCoordinator.parse_regulars_count(data),
        "endpoint_status": endpoint_status,
    }

    return {
        "entry": redact_data(dict(entry.data), TO_REDACT),
        "options": dict(entry.options),
        "summary": summary,
        "payload_shapes": {
            "cart": _describe_payload_shape(data.get("cart")),
            "shopping_lists": _describe_payload_shape(data.get("shopping_lists")),
            "recent_orders": _describe_payload_shape(data.get("recent_orders")),
            "orders_not_cancelled_count": _describe_payload_shape(data.get("orders_not_cancelled_count")),
            "regulars": _describe_payload_shape(data.get("regulars")),
        },
    }


def _describe_payload_shape(payload: Any) -> dict[str, Any]:
    """Return sanitized payload shape without exposing raw customer content."""
    if isinstance(payload, dict):
        return {
            "type": "dict",
            "keys": sorted(str(key) for key in payload.keys())[:30],
        }

    if isinstance(payload, list):
        first_item = payload[0] if payload else None
        first_item_type = type(first_item).__name__ if first_item is not None else None
        item_keys: list[str] | None = None
        if isinstance(first_item, dict):
            item_keys = sorted(str(key) for key in first_item.keys())[:30]

        return {
            "type": "list",
            "length": len(payload),
            "first_item_type": first_item_type,
            "first_item_keys": item_keys,
        }

    if payload is None:
        return {"type": "none"}

    return {"type": type(payload).__name__}
