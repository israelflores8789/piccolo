# Copyright 2026 Israel Flores-Arbolay
# SPDX-License-Identifier: Apache-2.0

"""privacy.py — Shared credential redaction at diagnostic and storage boundaries."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from piccolo.data import Document, Value

REDACTED = "[REDACTED]"
_KNOWN_SECRETS: set[str] = set()
_SENSITIVE = re.compile(
    r"(?i)(?:password|passwd|passphrase|secret|credential|authorization|"
    r"private.?key|access.?token|refresh.?token|id.?token|api.?key|client.?secret|"
    r"encryption.?key|signed.?url)"
)
_ASSIGNMENT = re.compile(
    r"(?i)(?<![\w./:-])([\"']?(?:[\w.-]*(?:password|passwd|passphrase|secret|credential|"
    r"private[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"api[_-]?key|client[_-]?secret|authorization|token)[\w.-]*)[\"']?\s*(?:=(?!=)|:(?!:))\s*)"
    r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;&}]+)"
)
_PEM = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY)-----.*?"
    r"(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)",
    re.DOTALL,
)


def sensitive_key(key: str) -> bool:
    """Classify credential fields while retaining public resource identifiers."""
    compact = re.sub(r"[^a-z0-9]", "", key.lower())
    if compact in {
        "secrets",
        "secretid",
        "secretids",
        "credentialfile",
        "privatekeypath",
        "privateinode",
        "privatedevice",
        "publickey",
        "publickeypath",
        "fingerprint",
        "key",
        "keys",
        "tokenuri",
        "impersonateserviceaccount",
        "connectionimpersonate",
        "requirepassphrase",
    }:
        return False
    return bool(_SENSITIVE.search(key)) or compact in {"token", "apikey", "keydata"}


def remember_secrets(data: Document) -> None:
    """Register substantial credential values for unlabelled diagnostic redaction."""
    for key, item in data.items():
        if sensitive_key(key) and isinstance(item, str) and len(item) >= 12:
            _KNOWN_SECRETS.add(item)
        elif isinstance(item, dict):
            remember_secrets(item)


def sanitize_text(message: str) -> str:
    """Hide private PEMs, labelled credentials, bearer tokens, and URL secrets."""
    result = message
    for secret in sorted(_KNOWN_SECRETS, key=len, reverse=True):
        result = result.replace(secret, REDACTED)
    result = _PEM.sub(REDACTED, result)
    result = re.sub(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", REDACTED, result)
    result = re.sub(r"\bya29\.[A-Za-z0-9._-]+", REDACTED, result)
    result = re.sub(r"\b1//[A-Za-z0-9_-]+", REDACTED, result)
    result = re.sub(r"\bAIza[A-Za-z0-9_-]{20,}\b", REDACTED, result)
    result = re.sub(
        r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", REDACTED, result
    )
    result = re.sub(r"(https?://)[^\s/@]+:[^\s/@]+@", r"\1" + REDACTED + "@", result)
    result = re.sub(
        r"(?i)([?&](?:x-goog-signature|x-goog-credential|signature|token|key)=)[^&#\s]+",
        r"\1" + REDACTED,
        result,
    )
    return _ASSIGNMENT.sub(lambda match: match[1] + REDACTED, result)


def sanitize(value: Value, *, diagnostic: bool = False) -> Value:
    """Copy JSON data, hiding credentials and opaque metadata before release.

    Args:
        value: JSON data to sanitize without changing the caller's live objects.
        diagnostic: Also hide free-form resource descriptions and label values.

    Returns:
        A sanitized copy retaining resource IDs and recovery request identities.
    """
    if isinstance(value, dict):
        result: Document = {}
        for key, item in value.items():
            if (
                sensitive_key(key)
                or key.lower() == "metadata"
                or (diagnostic and key.lower() in {"description", "labels"})
            ):
                result[key] = REDACTED
            else:
                result[key] = sanitize(item, diagnostic=diagnostic)
        return result
    if isinstance(value, list):
        return [sanitize(item, diagnostic=diagnostic) for item in value]
    return sanitize_text(value) if isinstance(value, str) else value


def resource_record(resource: Document) -> Document:
    """Keep recovery topology, omitting opaque text that must be reread from GCP."""
    return {
        key: item
        for key, item in resource.items()
        if key not in {"metadata", "description"}
    }
