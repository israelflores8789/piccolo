# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""data.py — Runtime-checked JSON values at persistence and SDK boundaries."""

import json
from collections.abc import Mapping, Sequence

from piccolo.errors import PiccoloError

type Value = str | int | float | bool | list[Value] | dict[str, Value] | None
type Document = dict[str, Value]


def value(raw: object) -> Value:
    """Validate a decoded value without introducing unchecked dynamic types."""
    if raw is None or isinstance(raw, str | int | float | bool):
        return raw
    if isinstance(raw, Mapping):
        result: Document = {}
        for key, item in raw.items():
            if not isinstance(key, str):
                raise PiccoloError("Expected a string dictionary key")
            result[key] = value(item)
        return result
    if isinstance(raw, Sequence) and not isinstance(raw, bytes):
        return [value(item) for item in raw]
    raise PiccoloError(f"Unsupported data value: {type(raw).__name__}")


def document(raw: object) -> Document:
    """Validate a JSON/TOML object."""
    checked = value(raw)
    if not isinstance(checked, dict):
        raise PiccoloError("Expected an object")
    return checked


def decode(text: str) -> Document:
    """Decode a JSON object and validate its shape."""
    raw: object = json.loads(text)
    return document(raw)


def text(data: Document, key: str, default: str = "") -> str:
    """Read a string field with runtime validation."""
    result = data.get(key, default)
    if not isinstance(result, str):
        raise PiccoloError(f"{key}: expected a string")
    return result


def objects(data: Document, key: str) -> list[Document]:
    """Read an array of objects."""
    result = data.get(key, [])
    if not isinstance(result, list):
        raise PiccoloError(f"{key}: expected an array")
    return [document(item) for item in result]
