"""Secret redaction for MCP responses and persistent audit metadata."""

from __future__ import annotations

import hashlib
import re
from typing import Iterable


LABELED_SECRET = re.compile(
    r"(?i)\b(bearer|token|api[_ -]?key|password|passwd|secret|community)"
    r"(?:\s*[:=]\s*|\s+)\S+"
)
CISCO_SECRET = re.compile(r"(?im)(\b(?:enable\s+)?(?:secret|password)(?:\s+\d+)?\s+)\S+")
SHADOW_HASH = re.compile(r"(?m)^([^:\r\n]+:)(?:[!*][^:\r\n]*|\$[^:\r\n]+)(?=:)")
FORTI_ENC = re.compile(r"\bENC\s+\S+")
PRIVATE_PEM = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.DOTALL,
)


def redact(text: object, secrets: Iterable[str] = (), limit: int | None = None) -> str:
    """Remove explicit credentials and key material while preserving diagnostic identifiers."""
    value = str(text)
    for secret in sorted({str(item) for item in secrets if len(str(item)) >= 3}, key=len, reverse=True):
        value = value.replace(secret, "<REDACTED>")
    value = PRIVATE_PEM.sub("<PRIVATE-KEY-REDACTED>", value)
    value = FORTI_ENC.sub("ENC <REDACTED>", value)
    value = SHADOW_HASH.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = CISCO_SECRET.sub(lambda match: match.group(1) + "<REDACTED>", value)
    value = LABELED_SECRET.sub(lambda match: f"{match.group(1)}=<REDACTED>", value)
    if limit is not None and len(value) > limit:
        raise ValueError("redacted output exceeds the explicit limit")
    return value


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
