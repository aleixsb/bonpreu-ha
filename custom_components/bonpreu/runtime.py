"""Runtime state types for Bonpreu integration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .api.client import BonpreuApiClient

if TYPE_CHECKING:
    from .coordinator import BonpreuDataUpdateCoordinator


@dataclass(slots=True)
class BonpreuRuntimeData:
    """Runtime entry state."""

    client: BonpreuApiClient
    coordinator: BonpreuDataUpdateCoordinator
