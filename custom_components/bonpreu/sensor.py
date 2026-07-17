"""Sensor platform for Bonpreu integration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import BonpreuDataUpdateCoordinator
from .runtime import BonpreuRuntimeData


@dataclass(frozen=True, kw_only=True)
class BonpreuSensorEntityDescription(SensorEntityDescription):
    """Bonpreu sensor entity description."""

    value_fn: Callable[[dict[str, Any]], Any]
    attrs_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None


SENSORS: tuple[BonpreuSensorEntityDescription, ...] = (
    BonpreuSensorEntityDescription(
        key="cart_total",
        name="Cart Total",
        icon="mdi:cart",
        device_class=SensorDeviceClass.MONETARY,
        native_unit_of_measurement="EUR",
        value_fn=BonpreuDataUpdateCoordinator.parse_cart_total,
        attrs_fn=lambda data: {
            "stale": _is_dataset_stale(data, "cart"),
        },
    ),
    BonpreuSensorEntityDescription(
        key="amount_to_free_delivery",
        name="Amount To Free Delivery",
        icon="mdi:truck-fast-outline",
        device_class=SensorDeviceClass.MONETARY,
        native_unit_of_measurement="EUR",
        value_fn=BonpreuDataUpdateCoordinator.parse_amount_to_free_delivery,
        attrs_fn=lambda data: {
            "stale": _is_dataset_stale(data, "cart"),
        },
    ),
    BonpreuSensorEntityDescription(
        key="cart_items_count",
        name="Cart Product Lines",
        icon="mdi:cart-outline",
        value_fn=BonpreuDataUpdateCoordinator.parse_cart_items_count,
        attrs_fn=lambda data: {
            "items_preview": BonpreuDataUpdateCoordinator.parse_cart_items_preview(data),
            "stale": _is_dataset_stale(data, "cart"),
        },
    ),
    BonpreuSensorEntityDescription(
        key="cart_units_count",
        name="Cart Units",
        icon="mdi:counter",
        value_fn=BonpreuDataUpdateCoordinator.parse_cart_units_count,
        attrs_fn=lambda data: {
            "stale": _is_dataset_stale(data, "cart"),
        },
    ),
    BonpreuSensorEntityDescription(
        key="shopping_lists_count",
        name="Shopping Lists",
        icon="mdi:format-list-checks",
        value_fn=BonpreuDataUpdateCoordinator.parse_shopping_lists_count,
        attrs_fn=lambda data: {
            "lists_preview": BonpreuDataUpdateCoordinator.parse_shopping_lists_preview(data),
            "stale": _is_dataset_stale(data, "shopping_lists"),
        },
    ),
    BonpreuSensorEntityDescription(
        key="recent_orders_count",
        name="Recent Orders",
        icon="mdi:history",
        value_fn=BonpreuDataUpdateCoordinator.parse_recent_orders_count,
        attrs_fn=lambda data: {
            "orders_preview": BonpreuDataUpdateCoordinator.parse_recent_orders_preview(data),
            "stale": _is_dataset_stale(data, "recent_orders"),
        },
    ),
    BonpreuSensorEntityDescription(
        key="orders_waiting_shipment_count",
        name="Orders Waiting Shipment",
        icon="mdi:truck-clock",
        value_fn=BonpreuDataUpdateCoordinator.parse_orders_waiting_shipment_count,
        attrs_fn=lambda data: {
            "orders_waiting_preview": BonpreuDataUpdateCoordinator.parse_orders_waiting_shipment_preview(data),
            "stale": _is_dataset_stale(data, "recent_orders"),
        },
    ),
    BonpreuSensorEntityDescription(
        key="active_orders_count",
        name="Active Orders",
        icon="mdi:truck-delivery-outline",
        value_fn=BonpreuDataUpdateCoordinator.parse_active_orders_count,
        attrs_fn=lambda data: {
            "stale": _is_dataset_stale(data, "orders_not_cancelled_count"),
        },
    ),
    BonpreuSensorEntityDescription(
        key="regulars_count",
        name="Regular Products",
        icon="mdi:star-box",
        value_fn=BonpreuDataUpdateCoordinator.parse_regulars_count,
        attrs_fn=lambda data: {
            "regular_products_preview": BonpreuDataUpdateCoordinator.parse_regulars_preview(data),
            "stale": _is_dataset_stale(data, "regulars"),
        },
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Bonpreu sensors from config entry."""
    runtime: BonpreuRuntimeData = hass.data[DOMAIN][entry.entry_id]
    coordinator = runtime.coordinator

    entities = [BonpreuSensor(coordinator, entry, description) for description in SENSORS]
    async_add_entities(entities)


class BonpreuSensor(CoordinatorEntity[BonpreuDataUpdateCoordinator], SensorEntity):
    """Bonpreu coordinator-backed sensor."""

    entity_description: BonpreuSensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: BonpreuDataUpdateCoordinator,
        entry: ConfigEntry,
        description: BonpreuSensorEntityDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=entry.title,
            manufacturer="Bonpreu",
            model="Online Shopping",
        )

    @property
    def native_value(self) -> Any:
        """Return current sensor value."""
        return self.entity_description.value_fn(self.coordinator.data or {})

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return extra attributes for richer shopping context."""
        if self.entity_description.attrs_fn is None:
            return None
        return self.entity_description.attrs_fn(self.coordinator.data or {})


def _is_dataset_stale(data: dict[str, Any], key: str) -> bool:
    status = (data.get("_endpoint_status") or {}).get(key)
    return status not in (None, "ok")
