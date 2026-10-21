"""Typed pipeline errors. Fail closed; never invent data."""

from __future__ import annotations


class PulseError(Exception):
    """Base error for the Security Pulse pipeline."""


class FetchError(PulseError):
    """Network, TLS, size, or redirect failure."""


class UnsafeRedirectError(FetchError):
    """Redirect target left the HTTPS host allowlist."""


class ValidationError(PulseError):
    """Source or snapshot failed structural validation."""


class CorrelationError(PulseError):
    """A CVE record did not match the requested identifier."""


class PublishGuardError(PulseError):
    """Refused to replace a valid published snapshot."""


class SourceDisabledError(PulseError):
    """Adapter is intentionally disabled."""
