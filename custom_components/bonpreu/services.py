"""Service handlers for Bonpreu integration."""

from __future__ import annotations

import re
from typing import Any, cast

import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ServiceValidationError
import homeassistant.helpers.config_validation as cv

from .const import (
    ATTR_CATEGORY_ID,
    ATTR_ENCODED_FILTERS,
    ATTR_QUERY,
    ATTR_INCLUDE_ADDITIONAL_PAGE_INFO,
    ATTR_QUANTITY,
    ATTR_DELTA,
    ATTR_ENTRY_ID,
    ATTR_LIST_ID,
    ATTR_LIST_NAME,
    ATTR_MAX_PAGE_SIZE,
    ATTR_PAGE_TOKEN,
    ATTR_PRODUCTS,
    ATTR_RETAILER_PRODUCT_ID,
    ATTR_SORT_OPTION_ID,
    ATTR_TARGET_QUANTITY,
    DOMAIN,
    SERVICE_ADD_SHOPPING_LIST_TO_CART,
    SERVICE_ADD_TO_CART,
    SERVICE_ADD_REGULAR_TO_CART,
    SERVICE_ADD_REGULAR_BY_ID_TO_CART,
    SERVICE_CREATE_SHOPPING_LIST,
    SERVICE_DELETE_SHOPPING_LIST,
    SERVICE_GET_CATALOG_PRODUCT_DETAIL,
    SERVICE_REMOVE_FROM_CART,
    SERVICE_RENAME_SHOPPING_LIST,
    SERVICE_SEARCH_CATALOG_PRODUCTS,
    SERVICE_SET_CART_QUANTITY,
)
from .runtime import BonpreuRuntimeData

_SERVICE_MARKER = f"{DOMAIN}_services_registered"

_LIST_PRODUCTS_LIMIT = 200
_LIST_NAME_MAX = 120


def _validate_non_empty_string(value: str) -> str:
    parsed = cv.string(value).strip()
    if not parsed:
        raise vol.Invalid("Value cannot be empty.")
    return parsed


def _validate_delta(value: int) -> int:
    parsed = vol.Coerce(int)(value)
    if parsed < -50 or parsed > 50:
        raise vol.Invalid("Delta must be between -50 and 50.")
    if parsed == 0:
        raise vol.Invalid("Delta cannot be zero.")
    return parsed


def _validate_target_quantity(value: int) -> int:
    parsed = vol.Coerce(int)(value)
    if parsed < 0 or parsed > 99:
        raise vol.Invalid("Target quantity must be between 0 and 99.")
    return parsed


def _validate_list_name(value: str) -> str:
    parsed = _validate_non_empty_string(value)
    if len(parsed) > _LIST_NAME_MAX:
        raise vol.Invalid(f"List name is too long (max {_LIST_NAME_MAX} chars).")
    return parsed


def _validate_products_list(value: Any) -> list[str]:
    parsed: list[Any]
    if isinstance(value, str):
        parsed = [part for part in re.split(r"[,\n]", value) if part.strip()]
    elif isinstance(value, dict):
        for key in ("products", "items", "product_ids"):
            nested = value.get(key)
            if isinstance(nested, list):
                parsed = nested
                break
        else:
            parsed = [item for item in value.values() if isinstance(item, str)]
    else:
        parsed = cv.ensure_list(value)

    cleaned = [_validate_non_empty_string(item) for item in parsed]
    if len(cleaned) > _LIST_PRODUCTS_LIMIT:
        raise vol.Invalid(f"Too many products (max {_LIST_PRODUCTS_LIMIT}).")
    return cleaned


_BASE_SCHEMA = vol.Schema({vol.Optional(ATTR_ENTRY_ID): cv.string})

_ADD_TO_CART_SCHEMA = _BASE_SCHEMA.extend(
    {
        vol.Required(ATTR_RETAILER_PRODUCT_ID): _validate_non_empty_string,
        vol.Optional(ATTR_DELTA, default=1): _validate_delta,
    }
)

_SET_CART_QUANTITY_SCHEMA = _BASE_SCHEMA.extend(
    {
        vol.Required(ATTR_RETAILER_PRODUCT_ID): _validate_non_empty_string,
        vol.Required(ATTR_TARGET_QUANTITY): _validate_target_quantity,
    }
)

_REMOVE_FROM_CART_SCHEMA = _BASE_SCHEMA.extend(
    {
        vol.Required(ATTR_RETAILER_PRODUCT_ID): _validate_non_empty_string,
    }
)

_LIST_ID_SCHEMA = _BASE_SCHEMA.extend({vol.Required(ATTR_LIST_ID): _validate_non_empty_string})

_CREATE_LIST_SCHEMA = _BASE_SCHEMA.extend(
    {
        vol.Required(ATTR_LIST_NAME): _validate_list_name,
        vol.Optional(ATTR_PRODUCTS, default=[]): _validate_products_list,
    }
)

_RENAME_LIST_SCHEMA = _BASE_SCHEMA.extend(
    {
        vol.Required(ATTR_LIST_ID): _validate_non_empty_string,
        vol.Required(ATTR_LIST_NAME): _validate_list_name,
    }
)

_ADD_REGULAR_TO_CART_SCHEMA = _BASE_SCHEMA.extend(
    {
        vol.Required(ATTR_QUERY): _validate_non_empty_string,
        vol.Optional(ATTR_QUANTITY, default=1): vol.All(vol.Coerce(int), vol.Range(min=1, max=50)),
    }
)

_ADD_REGULAR_BY_ID_TO_CART_SCHEMA = _BASE_SCHEMA.extend(
    {
        vol.Required(ATTR_RETAILER_PRODUCT_ID): _validate_non_empty_string,
        vol.Optional(ATTR_QUANTITY, default=1): vol.All(vol.Coerce(int), vol.Range(min=1, max=50)),
    }
)

_SEARCH_CATALOG_PRODUCTS_SCHEMA = _BASE_SCHEMA.extend(
    {
        vol.Required(ATTR_QUERY): _validate_non_empty_string,
        vol.Optional(ATTR_MAX_PAGE_SIZE, default=30): vol.All(vol.Coerce(int), vol.Range(min=1, max=100)),
        vol.Optional(ATTR_PAGE_TOKEN): _validate_non_empty_string,
        vol.Optional(ATTR_CATEGORY_ID): _validate_non_empty_string,
        vol.Optional(ATTR_ENCODED_FILTERS): _validate_non_empty_string,
        vol.Optional(ATTR_SORT_OPTION_ID): _validate_non_empty_string,
        vol.Optional(ATTR_INCLUDE_ADDITIONAL_PAGE_INFO, default=True): cv.boolean,
    }
)

_CATALOG_PRODUCT_DETAIL_SCHEMA = _BASE_SCHEMA.extend(
    {
        vol.Required(ATTR_RETAILER_PRODUCT_ID): _validate_non_empty_string,
    }
)


_SERVICE_NAMES: tuple[str, ...] = (
    SERVICE_ADD_TO_CART,
    SERVICE_SET_CART_QUANTITY,
    SERVICE_REMOVE_FROM_CART,
    SERVICE_ADD_REGULAR_TO_CART,
    SERVICE_ADD_REGULAR_BY_ID_TO_CART,
    SERVICE_ADD_SHOPPING_LIST_TO_CART,
    SERVICE_CREATE_SHOPPING_LIST,
    SERVICE_RENAME_SHOPPING_LIST,
    SERVICE_DELETE_SHOPPING_LIST,
    SERVICE_SEARCH_CATALOG_PRODUCTS,
    SERVICE_GET_CATALOG_PRODUCT_DETAIL,
)


async def async_register_services(hass: HomeAssistant) -> None:
    """Register Bonpreu domain services once."""
    if hass.data.get(_SERVICE_MARKER):
        return

    async def _handle_add_to_cart(call: ServiceCall) -> None:
        runtime = _resolve_runtime(hass, call)
        await runtime.coordinator.async_add_to_cart(
            retailer_product_id=call.data[ATTR_RETAILER_PRODUCT_ID],
            delta=call.data[ATTR_DELTA],
        )

    async def _handle_set_cart_quantity(call: ServiceCall) -> None:
        runtime = _resolve_runtime(hass, call)
        await runtime.coordinator.async_set_cart_quantity(
            retailer_product_id=call.data[ATTR_RETAILER_PRODUCT_ID],
            target_quantity=call.data[ATTR_TARGET_QUANTITY],
        )

    async def _handle_remove_from_cart(call: ServiceCall) -> None:
        runtime = _resolve_runtime(hass, call)
        await runtime.coordinator.async_set_cart_quantity(
            retailer_product_id=call.data[ATTR_RETAILER_PRODUCT_ID],
            target_quantity=0,
        )

    async def _handle_add_regular_to_cart(call: ServiceCall) -> None:
        runtime = _resolve_runtime(hass, call)
        query = call.data[ATTR_QUERY].strip().lower()
        quantity = call.data[ATTR_QUANTITY]

        regulars = runtime.coordinator.parse_regulars_preview(runtime.coordinator.data or {}, limit=500)
        if not regulars:
            raise ServiceValidationError("No regular products are available yet. Refresh and try again.")

        for product in regulars:
            product_id = str(product.get("retailer_product_id") or "").strip()
            product_name = str(product.get("name") or "").strip().lower()
            if not product_id:
                continue
            if query == product_id.lower() or query == product_name:
                await runtime.coordinator.async_add_to_cart(product_id, delta=quantity)
                return

        matches: list[dict[str, Any]] = []
        for product in regulars:
            product_id = str(product.get("retailer_product_id") or "").strip()
            product_name = str(product.get("name") or "").strip()
            if not product_id or not product_name:
                continue
            if query in product_name.lower():
                matches.append(product)

        if len(matches) == 1:
            await runtime.coordinator.async_add_to_cart(
                str(matches[0]["retailer_product_id"]),
                delta=quantity,
            )
            return

        if not matches:
            raise ServiceValidationError("No regular product matched the provided query.")

        raise ServiceValidationError(
            "Query matched multiple regular products. Use exact product ID or full name."
        )

    async def _handle_add_regular_by_id_to_cart(call: ServiceCall) -> None:
        runtime = _resolve_runtime(hass, call)
        retailer_product_id = call.data[ATTR_RETAILER_PRODUCT_ID].strip()
        quantity = call.data[ATTR_QUANTITY]

        regulars = runtime.coordinator.parse_regulars_preview(runtime.coordinator.data or {}, limit=500)
        regular_ids = {
            str(product.get("retailer_product_id") or "").strip().lower()
            for product in regulars
            if product.get("retailer_product_id")
        }
        if retailer_product_id.lower() not in regular_ids:
            raise ServiceValidationError(
                "Provided retailer_product_id is not present in regular products."
            )

        await runtime.coordinator.async_add_to_cart(retailer_product_id, delta=quantity)

    async def _handle_add_list_to_cart(call: ServiceCall) -> None:
        runtime = _resolve_runtime(hass, call)
        await runtime.coordinator.async_add_shopping_list_to_cart(call.data[ATTR_LIST_ID])

    async def _handle_create_list(call: ServiceCall) -> None:
        runtime = _resolve_runtime(hass, call)
        await runtime.coordinator.async_create_shopping_list(
            list_name=call.data[ATTR_LIST_NAME],
            products=call.data[ATTR_PRODUCTS],
        )

    async def _handle_rename_list(call: ServiceCall) -> None:
        runtime = _resolve_runtime(hass, call)
        await runtime.coordinator.async_rename_shopping_list(
            list_id=call.data[ATTR_LIST_ID],
            list_name=call.data[ATTR_LIST_NAME],
        )

    async def _handle_delete_list(call: ServiceCall) -> None:
        runtime = _resolve_runtime(hass, call)
        await runtime.coordinator.async_delete_shopping_list(call.data[ATTR_LIST_ID])

    async def _handle_search_catalog_products(call: ServiceCall) -> None:
        runtime = _resolve_runtime(hass, call)
        await runtime.coordinator.async_search_catalog_products(
            query=call.data[ATTR_QUERY],
            max_page_size=call.data[ATTR_MAX_PAGE_SIZE],
            page_token=call.data.get(ATTR_PAGE_TOKEN),
            category_id=call.data.get(ATTR_CATEGORY_ID),
            encoded_filters=call.data.get(ATTR_ENCODED_FILTERS),
            sort_option_id=call.data.get(ATTR_SORT_OPTION_ID),
            include_additional_page_info=call.data[ATTR_INCLUDE_ADDITIONAL_PAGE_INFO],
        )

    async def _handle_get_catalog_product_detail(call: ServiceCall) -> None:
        runtime = _resolve_runtime(hass, call)
        await runtime.coordinator.async_get_catalog_product_detail(call.data[ATTR_RETAILER_PRODUCT_ID])

    hass.services.async_register(
        DOMAIN,
        SERVICE_ADD_TO_CART,
        _handle_add_to_cart,
        schema=_ADD_TO_CART_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_SET_CART_QUANTITY,
        _handle_set_cart_quantity,
        schema=_SET_CART_QUANTITY_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_REMOVE_FROM_CART,
        _handle_remove_from_cart,
        schema=_REMOVE_FROM_CART_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_ADD_REGULAR_TO_CART,
        _handle_add_regular_to_cart,
        schema=_ADD_REGULAR_TO_CART_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_ADD_REGULAR_BY_ID_TO_CART,
        _handle_add_regular_by_id_to_cart,
        schema=_ADD_REGULAR_BY_ID_TO_CART_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_ADD_SHOPPING_LIST_TO_CART,
        _handle_add_list_to_cart,
        schema=_LIST_ID_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_CREATE_SHOPPING_LIST,
        _handle_create_list,
        schema=_CREATE_LIST_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_RENAME_SHOPPING_LIST,
        _handle_rename_list,
        schema=_RENAME_LIST_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_DELETE_SHOPPING_LIST,
        _handle_delete_list,
        schema=_LIST_ID_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_SEARCH_CATALOG_PRODUCTS,
        _handle_search_catalog_products,
        schema=_SEARCH_CATALOG_PRODUCTS_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_GET_CATALOG_PRODUCT_DETAIL,
        _handle_get_catalog_product_detail,
        schema=_CATALOG_PRODUCT_DETAIL_SCHEMA,
    )

    hass.data[_SERVICE_MARKER] = True


async def async_unregister_services(hass: HomeAssistant) -> None:
    """Unregister Bonpreu services when no entries remain."""
    if not hass.data.get(_SERVICE_MARKER):
        return

    if hass.data.get(DOMAIN):
        return

    for service_name in _SERVICE_NAMES:
        if hass.services.has_service(DOMAIN, service_name):
            hass.services.async_remove(DOMAIN, service_name)

    hass.data.pop(_SERVICE_MARKER, None)


def _resolve_runtime(hass: HomeAssistant, call: ServiceCall) -> BonpreuRuntimeData:
    entries: dict[str, BonpreuRuntimeData] = hass.data.get(DOMAIN, {})
    if not entries:
        raise ServiceValidationError("No Bonpreu entries are loaded.")

    requested_entry_id = cast(str | None, call.data.get(ATTR_ENTRY_ID))
    if requested_entry_id:
        runtime = entries.get(requested_entry_id)
        if runtime is None:
            raise ServiceValidationError(f"Entry '{requested_entry_id}' not found.")
        return runtime

    if len(entries) > 1:
        raise ServiceValidationError(
            "Multiple Bonpreu entries found. Provide 'entry_id' in service data."
        )

    return next(iter(entries.values()))
