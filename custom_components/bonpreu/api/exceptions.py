"""API exceptions for Bonpreu."""

from __future__ import annotations


class BonpreuError(Exception):
    """Base integration error."""


class BonpreuApiError(BonpreuError):
    """Raised for API responses outside expected behavior."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class BonpreuAuthError(BonpreuApiError):
    """Raised when authentication is invalid or expired."""


class BonpreuConfigError(BonpreuError):
    """Raised for configuration-flow errors."""
