"""Exceptions raised by the Elements API client."""

from __future__ import annotations


class ElementsApiError(Exception):
    """An API call failed (after retries, when applicable)."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        code: int | str | None = None,
        transaction_id: str | None = None,
        details: object = None,
    ):
        super().__init__(message)
        self.status = status
        self.code = code
        self.transaction_id = transaction_id
        self.details = details

    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.status is not None:
            parts.append(f"status={self.status}")
        if self.code is not None:
            parts.append(f"code={self.code}")
        if self.transaction_id:
            parts.append(f"transactionId={self.transaction_id}")
        if self.details:
            parts.append(f"details={self.details}")
        return " ".join(parts)


class AuthenticationError(ElementsApiError):
    """Token request rejected (bad credentials, scope not allowed, ...)."""


class ReadOnlyViolation(RuntimeError):
    """Raised before sending any request that is not on the read-only allowlist."""
