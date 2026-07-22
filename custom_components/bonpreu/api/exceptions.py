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


class BonpreuLoginError(BonpreuConfigError):
    """Raised for credential-based login flow failures."""


class BonpreuCredentialConfigError(BonpreuLoginError):
    """Raised when YAML credentials are missing or invalid."""


class BonpreuInvalidCredentialsError(BonpreuLoginError):
    """Raised when username/password were rejected."""


class BonpreuInvalidEmailCodeError(BonpreuLoginError):
    """Raised when the email verification code is invalid."""


class BonpreuLoginChallengeError(BonpreuLoginError):
    """Raised when login requires browser-only challenges (captcha/waf)."""


class BonpreuLoginFormError(BonpreuLoginError):
    """Raised when expected login forms cannot be parsed."""


class BonpreuLoginExpiredError(BonpreuLoginError):
    """Raised when credential login transaction expires."""
