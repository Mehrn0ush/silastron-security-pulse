"""Typed pipeline errors. Fail closed; never invent data."""

from __future__ import annotations


class PulseError(Exception):
    """Base error for the Security Pulse pipeline."""


class FetchError(PulseError):
    """Network, TLS, size, or redirect failure."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        retry_after: float | None = None,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.retry_after = retry_after
        self.status_code = status_code


class UnsafeRedirectError(FetchError):
    """Redirect target left the HTTPS host allowlist."""


class ValidationError(PulseError):
    """Source or snapshot failed structural validation."""


class CorrelationError(PulseError):
    """A CVE record did not match the requested identifier."""


class PublishGuardError(PulseError):
    """Refused to replace a valid published snapshot."""


class ArtifactVerifyError(PublishGuardError):
    """Collection artifact failed identity or integrity checks."""


class SourceDisabledError(PulseError):
    """Adapter is intentionally disabled."""
