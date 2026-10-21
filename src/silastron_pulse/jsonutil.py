"""Bounded JSON parsing and canonical serialization."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from silastron_pulse.errors import ValidationError


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_bounded_json(
    data: bytes,
    *,
    max_bytes: int,
    max_depth: int,
    source: str,
) -> Any:
    if len(data) > max_bytes:
        raise ValidationError(
            f"{source} exceeded max bytes {max_bytes} (got {len(data)})"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{source} is not valid UTF-8") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"{source} is not valid JSON: {exc}") from exc
    _assert_depth(payload, max_depth=max_depth, source=source)
    return payload


def _assert_depth(value: Any, *, max_depth: int, source: str, depth: int = 0) -> None:
    if depth > max_depth:
        raise ValidationError(f"{source} JSON nesting exceeded {max_depth}")
    if isinstance(value, dict):
        for item in value.values():
            _assert_depth(item, max_depth=max_depth, source=source, depth=depth + 1)
    elif isinstance(value, list):
        for item in value:
            _assert_depth(item, max_depth=max_depth, source=source, depth=depth + 1)


def dump_canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def dump_bytes(payload: Any) -> bytes:
    return dump_canonical(payload).encode("utf-8")
