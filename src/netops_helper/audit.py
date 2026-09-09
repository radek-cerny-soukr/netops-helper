"""Secret-free JSONL audit records."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
from typing import Any


AUDIT_PATH = Path("/var/lib/netops-helper/audit.jsonl")
AUDIT_SEGMENT_BYTES = 2_000_000
AUDIT_RETAINED_SEGMENTS = 5
_LOCK = threading.Lock()


def _segment(path: Path, index: int) -> Path:
    return path if index == 0 else path.with_name(f"{path.name}.{index}")


def _rotate(path: Path, incoming_bytes: int) -> None:
    """Keep the active log and four backups within a fixed 10 MB budget."""
    if incoming_bytes > AUDIT_SEGMENT_BYTES:
        raise ValueError("audit record exceeds segment limit")
    try:
        current_size = path.stat().st_size
    except FileNotFoundError:
        return
    if current_size + incoming_bytes <= AUDIT_SEGMENT_BYTES:
        return

    oldest = _segment(path, AUDIT_RETAINED_SEGMENTS - 1)
    oldest.unlink(missing_ok=True)
    for index in range(AUDIT_RETAINED_SEGMENTS - 2, 0, -1):
        source = _segment(path, index)
        if source.exists():
            os.replace(source, _segment(path, index + 1))
    os.replace(path, _segment(path, 1))
    os.chmod(_segment(path, 1), 0o600)


def record(event: str, **fields: Any) -> None:
    allowed = {
        "target", "status", "query", "platform", "port", "count", "max_hops",
        "item_count", "offset", "max_bytes", "total_bytes", "returned_bytes",
        "path_sha256", "result_sha256", "use_tls", "use_basic_auth",
        "plaintext_acknowledged", "pagination_source", "detail",
    }
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **{key: value for key, value in fields.items() if key in allowed},
    }
    encoded = (json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        _rotate(AUDIT_PATH, len(encoded))
        AUDIT_PATH.touch(mode=0o600, exist_ok=True)
        os.chmod(AUDIT_PATH, 0o600)
        with AUDIT_PATH.open("ab") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
