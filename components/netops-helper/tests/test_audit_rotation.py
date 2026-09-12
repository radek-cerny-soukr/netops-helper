from __future__ import annotations

import json
from pathlib import Path
import stat
import tempfile as temporary_directory

import netops_helper.audit as audit


def test_audit_rotates_and_enforces_total_budget(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "AUDIT_PATH", path)
    monkeypatch.setattr(audit, "AUDIT_SEGMENT_BYTES", 260)
    monkeypatch.setattr(audit, "AUDIT_RETAINED_SEGMENTS", 3)

    for index in range(30):
        audit.record("test", target="device-a", status="ok", detail=f"event-{index:02d}")

    segments = sorted(tmp_path.glob("audit.jsonl*"))
    assert [item.name for item in segments] == ["audit.jsonl", "audit.jsonl.1", "audit.jsonl.2"]
    assert sum(item.stat().st_size for item in segments) <= 780
    assert all(stat.S_IMODE(item.stat().st_mode) == 0o600 for item in segments)
    for item in segments:
        assert all(json.loads(line)["event"] == "test" for line in item.read_text().splitlines())


def test_audit_keeps_read_metadata_and_drops_phase2_fields(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "AUDIT_PATH", path)
    audit.record(
        "ssh_read", target="device-a", status="ok", query="interface_details",
        total_bytes=1234, result_sha256="a" * 64,
        change_id="dead-field", command_count=99, persistent=True,
    )
    payload = json.loads(path.read_text())
    assert payload["query"] == "interface_details"
    assert payload["total_bytes"] == 1234
    for dead in ("change_id", "command_count", "persistent"):
        assert dead not in payload


def test_audit_rejects_record_larger_than_segment(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(audit, "AUDIT_PATH", tmp_path / "audit.jsonl")
    monkeypatch.setattr(audit, "AUDIT_SEGMENT_BYTES", 64)
    try:
        audit.record("test", detail="x" * 200)
    except ValueError as exc:
        assert "segment limit" in str(exc)
    else:
        raise AssertionError("oversized audit record was accepted")

def _assert_operation_id_contract(path: Path) -> None:
    previous = audit.AUDIT_PATH
    audit.AUDIT_PATH = path
    try:
        operation_id = "op_" + "a" * 32
        audit.record(
            "ssh_read", operation_id=operation_id,
            target="device-a", status="started",
        )
        payload = json.loads(path.read_text())
        assert payload["operation_id"] == operation_id

        invalid = (
            None,
            7,
            "",
            "a" * 32,
            "op_" + "A" * 32,
            "op_" + "a" * 31,
            "op_" + "a" * 33,
            "op_" + "../secret-input",
        )
        for value in invalid:
            try:
                audit.record("ssh_read", operation_id=value, status="started")
            except ValueError:
                pass
            else:
                raise AssertionError(f"invalid operation_id was accepted: {value!r}")
        assert len(path.read_text().splitlines()) == 1
    finally:
        audit.AUDIT_PATH = previous


def test_audit_operation_id_has_exact_allowlisted_format(tmp_path: Path) -> None:
    _assert_operation_id_contract(tmp_path / "operation-id.jsonl")


def main() -> int:
    with temporary_directory.TemporaryDirectory() as raw:
        _assert_operation_id_contract(Path(raw) / "operation-id.jsonl")
    print("audit_contract_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
