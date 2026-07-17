"""To-do platform for Bonpreu integration."""

from __future__ import annotations

import re
from typing import Any

from homeassistant.components.todo import (
    TodoItem,
    TodoItemStatus,
    TodoListEntity,
    TodoListEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import BonpreuDataUpdateCoordinator
from .runtime import BonpreuRuntimeData


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Bonpreu to-do entities from config entry."""
    runtime: BonpreuRuntimeData = hass.data[DOMAIN][entry.entry_id]
    coordinator = runtime.coordinator

    async_add_entities(
        [
            BonpreuCartTodoEntity(coordinator, entry),
            BonpreuRegularsTodoEntity(coordinator, entry),
            BonpreuOrdersWaitingTodoEntity(coordinator, entry),
        ]
    )


class BonpreuBaseTodoEntity(CoordinatorEntity[BonpreuDataUpdateCoordinator], TodoListEntity):
    """Shared base for Bonpreu todo entities."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: BonpreuDataUpdateCoordinator,
        entry: ConfigEntry,
        *,
        unique_suffix: str,
        name: str,
        icon: str,
    ) -> None:
        super().__init__(coordinator)
        self._attr_name = name
        self._attr_icon = icon
        self._attr_unique_id = f"{entry.entry_id}_{unique_suffix}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=entry.title,
            manufacturer="Bonpreu",
            model="Online Shopping",
        )


class BonpreuCartTodoEntity(BonpreuBaseTodoEntity):
    """To-do entity representing current cart lines."""

    _attr_supported_features = (
        TodoListEntityFeature.CREATE_TODO_ITEM
        | TodoListEntityFeature.UPDATE_TODO_ITEM
        | TodoListEntityFeature.DELETE_TODO_ITEM
        | TodoListEntityFeature.SET_DESCRIPTION_ON_ITEM
    )

    def __init__(self, coordinator: BonpreuDataUpdateCoordinator, entry: ConfigEntry) -> None:
        super().__init__(
            coordinator,
            entry,
            unique_suffix="cart_todo",
            name="Cart Items",
            icon="mdi:cart",
        )

    @property
    def todo_items(self) -> list[TodoItem] | None:
        """Return cart lines as todo items."""
        items = BonpreuDataUpdateCoordinator.parse_cart_items_preview(self.coordinator.data or {}, limit=500)
        result: list[TodoItem] = []
        for item in items:
            retailer_product_id = str(item.get("retailer_product_id") or "")
            if not retailer_product_id:
                continue

            description_parts: list[str] = [f"id={retailer_product_id}"]
            quantity = int(item.get("quantity") or 0)
            description_parts.append(f"qty={quantity}")
            unit_price = item.get("unit_price")
            line_total = item.get("line_total")
            if unit_price is not None:
                description_parts.append(f"unit_price={unit_price}")
            if line_total is not None:
                description_parts.append(f"line_total={line_total}")

            result.append(
                TodoItem(
                    uid=retailer_product_id,
                    summary=str(item.get("name") or retailer_product_id),
                    status=TodoItemStatus.NEEDS_ACTION,
                    description="; ".join(description_parts),
                )
            )

        return result

    async def async_create_todo_item(self, item: TodoItem) -> None:
        """Add an item to cart using product id/name in summary."""
        summary = (item.summary or "").strip()
        if not summary:
            raise HomeAssistantError("Missing product identifier in todo summary.")

        retailer_product_id = _resolve_product_id(self.coordinator, summary)
        if not retailer_product_id:
            raise HomeAssistantError("Could not resolve product id from todo summary.")

        quantity = _extract_quantity_hint(item)
        await self.coordinator.async_add_to_cart(retailer_product_id, delta=quantity)

    async def async_update_todo_item(self, item: TodoItem) -> None:
        """Update cart item by changing qty via description or marking completed."""
        uid = (item.uid or "").strip()
        if not uid:
            raise HomeAssistantError("Missing todo item uid.")

        if item.status == TodoItemStatus.COMPLETED:
            await self.coordinator.async_set_cart_quantity(uid, target_quantity=0)
            return

        quantity = _extract_quantity_hint(item)
        await self.coordinator.async_set_cart_quantity(uid, target_quantity=quantity)

    async def async_delete_todo_items(self, uids: list[str]) -> None:
        """Delete cart lines by setting their quantity to zero."""
        for uid in uids:
            cleaned_uid = uid.strip()
            if not cleaned_uid:
                continue
            await self.coordinator.async_set_cart_quantity(cleaned_uid, target_quantity=0)


class BonpreuRegularsTodoEntity(BonpreuBaseTodoEntity):
    """Read-only to-do entity exposing regular products for quick reference."""

    _attr_supported_features = (
        TodoListEntityFeature.CREATE_TODO_ITEM
        | TodoListEntityFeature.UPDATE_TODO_ITEM
        | TodoListEntityFeature.SET_DESCRIPTION_ON_ITEM
    )

    def __init__(self, coordinator: BonpreuDataUpdateCoordinator, entry: ConfigEntry) -> None:
        super().__init__(
            coordinator,
            entry,
            unique_suffix="regulars_todo",
            name="Regular Products",
            icon="mdi:star-box",
        )

    @property
    def todo_items(self) -> list[TodoItem] | None:
        """Return regular products as todo items."""
        products = BonpreuDataUpdateCoordinator.parse_regulars_preview(self.coordinator.data or {}, limit=500)
        result: list[TodoItem] = []
        for product in products:
            retailer_product_id = str(product.get("retailer_product_id") or "")
            if not retailer_product_id:
                continue

            price = product.get("price")
            description = f"id={retailer_product_id}"
            if price is not None:
                description = f"{description}; price={price}"

            result.append(
                TodoItem(
                    uid=retailer_product_id,
                    summary=str(product.get("name") or retailer_product_id),
                    status=TodoItemStatus.NEEDS_ACTION,
                    description=description,
                )
            )

        return result

    async def async_create_todo_item(self, item: TodoItem) -> None:
        """Quick-add a regular product from todo summary text."""
        summary = (item.summary or "").strip()
        if not summary:
            raise HomeAssistantError("Missing regular product identifier in todo summary.")

        retailer_product_id = _resolve_regular_product_id(self.coordinator, summary)
        if not retailer_product_id:
            raise HomeAssistantError("Could not resolve regular product from todo summary.")

        quantity = _extract_quantity_hint(item)
        await self.coordinator.async_add_to_cart(retailer_product_id, delta=quantity)

    async def async_update_todo_item(self, item: TodoItem) -> None:
        """Marking a regular product completed adds it to the cart."""
        if item.status != TodoItemStatus.COMPLETED:
            return

        uid = (item.uid or "").strip()
        if not uid:
            raise HomeAssistantError("Missing regular product uid.")

        quantity = _extract_quantity_hint(item)
        await self.coordinator.async_add_to_cart(uid, delta=quantity)


class BonpreuOrdersWaitingTodoEntity(BonpreuBaseTodoEntity):
    """Read-only to-do entity showing orders that are pending shipment."""

    _attr_supported_features = 0

    def __init__(self, coordinator: BonpreuDataUpdateCoordinator, entry: ConfigEntry) -> None:
        super().__init__(
            coordinator,
            entry,
            unique_suffix="orders_waiting_todo",
            name="Orders Waiting Shipment",
            icon="mdi:truck-clock",
        )

    @property
    def todo_items(self) -> list[TodoItem] | None:
        """Return pending-shipment orders as todo items."""
        orders = BonpreuDataUpdateCoordinator.parse_orders_waiting_shipment_preview(
            self.coordinator.data or {},
            limit=500,
        )
        result: list[TodoItem] = []
        for order in orders:
            order_id = str(order.get("order_id") or "").strip()
            if not order_id:
                continue

            status = str(order.get("status") or "pending")
            summary = f"{order_id} ({status})"
            description_parts: list[str] = []
            created_at = order.get("created_at")
            total = order.get("total")
            item_count = order.get("item_count")
            items_preview = order.get("items_preview")

            if created_at:
                description_parts.append(f"created_at={created_at}")
            if total is not None:
                description_parts.append(f"total={total}")
            if item_count is not None:
                description_parts.append(f"item_count={item_count}")
            if isinstance(items_preview, list) and items_preview:
                description_parts.append(f"items={', '.join(str(item) for item in items_preview[:6])}")

            result.append(
                TodoItem(
                    uid=order_id,
                    summary=summary,
                    status=TodoItemStatus.NEEDS_ACTION,
                    description="; ".join(description_parts) if description_parts else None,
                )
            )

        return result


def _extract_quantity_hint(item: TodoItem) -> int:
    for candidate in (item.description or "", item.summary or ""):
        match = re.search(r"(?:qty|quantity|x)\s*[=:]?\s*(\d+)", candidate, re.IGNORECASE)
        if match:
            quantity = int(match.group(1))
            if 0 <= quantity <= 99:
                return quantity
    return 1


def _resolve_product_id(coordinator: BonpreuDataUpdateCoordinator, text: str) -> str | None:
    candidate = text.strip()
    if not candidate:
        return None

    id_match = re.search(r"(?:id\s*[=:]\s*)?([A-Za-z0-9_-]{4,})", candidate)
    direct_candidate = id_match.group(1) if id_match else candidate

    cart_items = BonpreuDataUpdateCoordinator.parse_cart_items_preview(coordinator.data or {}, limit=500)
    regulars = BonpreuDataUpdateCoordinator.parse_regulars_preview(coordinator.data or {}, limit=500)
    products = [*cart_items, *regulars]

    lower_candidate = candidate.lower()
    lower_direct = direct_candidate.lower()

    for product in products:
        product_id = str(product.get("retailer_product_id") or "")
        if product_id and product_id.lower() in {lower_candidate, lower_direct}:
            return product_id

    for product in products:
        product_name = str(product.get("name") or "")
        product_id = str(product.get("retailer_product_id") or "")
        if product_name and product_id and product_name.lower() == lower_candidate:
            return product_id

    fuzzy_matches: list[str] = []
    for product in products:
        product_name = str(product.get("name") or "")
        product_id = str(product.get("retailer_product_id") or "")
        if product_name and product_id and lower_candidate in product_name.lower():
            fuzzy_matches.append(product_id)

    if len(fuzzy_matches) == 1:
        return fuzzy_matches[0]

    return direct_candidate if direct_candidate else None


def _resolve_regular_product_id(coordinator: BonpreuDataUpdateCoordinator, text: str) -> str | None:
    candidate = text.strip()
    if not candidate:
        return None

    direct_match = re.search(r"(?:id\s*[=:]\s*)?([A-Za-z0-9_-]{4,})", candidate)
    direct_candidate = direct_match.group(1) if direct_match else candidate

    products = BonpreuDataUpdateCoordinator.parse_regulars_preview(coordinator.data or {}, limit=500)
    lower_candidate = candidate.lower()
    lower_direct = direct_candidate.lower()

    for product in products:
        product_id = str(product.get("retailer_product_id") or "")
        if product_id and product_id.lower() in {lower_candidate, lower_direct}:
            return product_id

    for product in products:
        product_name = str(product.get("name") or "")
        product_id = str(product.get("retailer_product_id") or "")
        if product_name and product_id and product_name.lower() == lower_candidate:
            return product_id

    fuzzy_matches: list[str] = []
    for product in products:
        product_name = str(product.get("name") or "")
        product_id = str(product.get("retailer_product_id") or "")
        if product_name and product_id and lower_candidate in product_name.lower():
            fuzzy_matches.append(product_id)

    if len(fuzzy_matches) == 1:
        return fuzzy_matches[0]

    return None
