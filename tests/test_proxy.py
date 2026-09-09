from __future__ import annotations

from base64 import urlsafe_b64decode
import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "remote_mcp_proxy.py"
SPEC = importlib.util.spec_from_file_location("remote_mcp_proxy", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_schema_hides_internal_auth_field() -> None:
    proxy = MODULE.Proxy(); proxy.pending[7] = "tools/list"
    response = {"jsonrpc": "2.0", "id": 7, "result": {"tools": [{
        "name": "tcp_probe",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}, "auth_context": {"type": "string"}},
            "required": ["target", "auth_context"],
        },
    }]}}
    schema = json.loads(proxy.response(json.dumps(response).encode()))["result"]["tools"][0]["inputSchema"]
    assert "auth_context" not in schema["properties"]
    assert "auth_context" not in schema["required"]


def _write_test_vault(path: Path) -> None:
    path.write_text(json.dumps({
        "other": {
            "host": "unrelated-host", "port": 22,
            "login": "unrelated-user", "password": "unrelated-secret",
        },
        "device-a": {
            "host": "selected-host", "port": 22,
            "login": "selected-user", "password": "selected-secret",
        },
    }, indent=2) + "\n")
    path.chmod(0o600)


def _policy(path: Path) -> None:
    path.write_text(json.dumps({"device-a": {
        "account_role": "read-only",
        "read_inventory": {"interfaces": ["eth0"], "services": [], "addresses": []},
        "https_endpoints": [{"path": "/status", "port": 443, "use_basic_auth": False}],
        "sftp_roots": ["/safe"],
        "fortios_output_standard_verified": True,
        "rate_limit": {"requests": 2, "window_seconds": 60},
    }}))


def test_load_record_accepts_pretty_printed_json(tmp_path: Path, monkeypatch) -> None:
    vault = tmp_path / "vault.json"
    _write_test_vault(vault)
    monkeypatch.setattr(MODULE, "VAULT", vault)
    assert MODULE.Proxy()._load_record("device-a")["login"] == "selected-user"
    with pytest.raises(ValueError):
        MODULE.Proxy()._load_record("missing")


def test_load_record_rejects_loose_permissions(tmp_path: Path, monkeypatch) -> None:
    vault = tmp_path / "vault.json"
    _write_test_vault(vault)
    vault.chmod(0o644)
    monkeypatch.setattr(MODULE, "VAULT", vault)
    with pytest.raises(ValueError):
        MODULE.Proxy()._load_record("device-a")


def test_request_injects_read_only_scope_and_only_password_is_secret(tmp_path: Path, monkeypatch) -> None:
    vault=tmp_path/"vault.json"; known=tmp_path/"known_hosts"; policy=tmp_path/"target-policy.json"
    _write_test_vault(vault); known.write_text("test-key-material"); _policy(policy)
    monkeypatch.setattr(MODULE,"VAULT",vault); monkeypatch.setattr(MODULE,"KNOWN_HOSTS",known); monkeypatch.setattr(MODULE,"TARGET_POLICY",policy)
    proxy=MODULE.Proxy()
    transformed=proxy.request(json.dumps({
        "jsonrpc":"2.0","id":21,"method":"tools/call",
        "params":{"name":"ssh_read","arguments":{"target":"device-a"}},
    }).encode())
    assert transformed is not None
    assert proxy.response_secrets[21] == ("selected-secret",)
    encoded=json.loads(transformed)["params"]["arguments"]["auth_context"]
    scope=json.loads(urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert scope["account_role"] == "read-only"
    assert scope["read_inventory"]["interfaces"] == ["eth0"]
    assert scope["sftp_roots"] == ["/safe"]
    assert scope["https_endpoints"] == [
        {"path": "/status", "port": 443, "use_basic_auth": False},
    ]
    assert scope["fortios_output_standard_verified"] is True
    assert "rate_limit" not in scope


def test_missing_read_only_enrollment_fails_closed(tmp_path: Path, monkeypatch) -> None:
    policy=tmp_path/"target-policy.json"; policy.write_text("{}")
    monkeypatch.setattr(MODULE,"TARGET_POLICY",policy)
    with pytest.raises(ValueError): MODULE.Proxy()._load_target_policy("device-a")


def test_response_preserves_identifiers_redacts_secret_and_marks_untrusted() -> None:
    proxy=MODULE.Proxy(); proxy.pending[22]="tools/call"; proxy.response_secrets[22]=("credential-value",)
    raw=json.dumps({
        "jsonrpc":"2.0","id":22,
        "result":{"content":[{"type":"text","text":"Sep 9 10:23:45 host ip=192.0.2.10 mac=aa:bb:cc:dd:ee:ff credential-value"}]},
    }).encode()
    transformed=json.loads(proxy.response(raw)); output=transformed["result"]["content"][0]["text"]
    assert output.startswith("UNTRUSTED DEVICE DATA")
    for visible in ("10:23:45", "host", "192.0.2.10", "aa:bb:cc:dd:ee:ff"): assert visible in output
    assert "credential-value" not in output
    assert transformed["result"]["_meta"]["netops/device-output-trust"] == "untrusted"


def test_tools_list_error_response_does_not_crash() -> None:
    proxy = MODULE.Proxy(); proxy.pending[23] = "tools/list"
    response = {"jsonrpc": "2.0", "id": 23, "error": {"code": -32603, "message": "failed"}}
    assert json.loads(proxy.response(json.dumps(response).encode())) == response
    assert 23 not in proxy.pending


def test_server_request_id_collision_does_not_consume_pending_response() -> None:
    proxy = MODULE.Proxy(); proxy.pending[1] = "tools/call"
    proxy.response_secrets[1] = ("credential-value",)
    server_request = {"jsonrpc": "2.0", "id": 1, "method": "sampling/createMessage", "params": {}}
    assert json.loads(proxy.response(json.dumps(server_request).encode())) == server_request
    assert proxy.pending[1] == "tools/call"
    actual = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "credential-value"}]}}
    transformed = json.loads(proxy.response(json.dumps(actual).encode()))
    assert "credential-value" not in transformed["result"]["content"][0]["text"]
    assert 1 not in proxy.pending


def test_batch_is_rejected_without_crashing(monkeypatch) -> None:
    proxy = MODULE.Proxy(); emitted = []
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    assert proxy.request(b"[]") is None
    assert emitted[0]["error"]["code"] == -32600


def test_master_alias_is_never_addressable(monkeypatch) -> None:
    proxy = MODULE.Proxy(); emitted = []
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    monkeypatch.setattr(proxy, "_load_record", lambda alias: (_ for _ in ()).throw(AssertionError()))
    request = {"jsonrpc": "2.0", "id": 30, "method": "tools/call", "params": {
        "name": "tcp_probe", "arguments": {"target": MODULE.MASTER_ALIAS, "port": 22},
    }}
    assert proxy.request(json.dumps(request).encode()) is None
    assert emitted[0]["error"]["code"] == -32602


def test_per_target_rate_limit_fails_closed(monkeypatch) -> None:
    proxy = MODULE.Proxy()
    ticks = iter((100.0, 101.0, 102.0, 200.0))
    monkeypatch.setattr(MODULE.time, "monotonic", lambda: next(ticks))
    policy = {"requests": 2, "window_seconds": 60}
    proxy._consume_rate_limit("device-a", policy)
    proxy._consume_rate_limit("device-a", policy)
    with pytest.raises(ValueError, match="rate limit"):
        proxy._consume_rate_limit("device-a", policy)
    proxy._consume_rate_limit("device-a", policy)


def test_malformed_tool_params_and_request_id_are_rejected(monkeypatch) -> None:
    proxy = MODULE.Proxy(); emitted = []
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    malformed = {"jsonrpc": "2.0", "id": 40, "method": "tools/call", "params": []}
    assert proxy.request(json.dumps(malformed).encode()) is None
    assert emitted[-1]["error"]["code"] == -32602
    bad_id = {"jsonrpc": "2.0", "id": [], "method": "tools/list"}
    assert proxy.request(json.dumps(bad_id).encode()) is None
    assert emitted[-1]["error"]["code"] == -32600


def test_duplicate_pending_request_id_is_rejected(monkeypatch) -> None:
    proxy = MODULE.Proxy(); emitted = []; proxy.pending[41] = "tools/list"
    monkeypatch.setattr(proxy, "_emit", emitted.append)
    duplicate = {"jsonrpc": "2.0", "id": 41, "method": "tools/list"}
    assert proxy.request(json.dumps(duplicate).encode()) is None
    assert emitted[-1]["error"]["code"] == -32600
    assert proxy.pending[41] == "tools/list"


def test_batched_server_responses_are_sanitized() -> None:
    proxy = MODULE.Proxy(); proxy.pending[50] = "tools/call"; proxy.pending[51] = "tools/list"
    proxy.response_secrets[50] = ("credential-value",)
    batch = [
        {"jsonrpc": "2.0", "id": 50, "result": {
            "structuredContent": {"snmp_community": "private-value"},
            "content": [{"type": "text", "text": "credential-value"}],
        }},
        {"jsonrpc": "2.0", "id": 51, "error": {"code": -32603, "message": "failed"}},
    ]
    transformed = json.loads(proxy.response(json.dumps(batch).encode()))
    assert transformed[0]["result"]["structuredContent"]["snmp_community"] == "<REDACTED>"
    assert "credential-value" not in transformed[0]["result"]["content"][0]["text"]
    assert transformed[1] == batch[1]
    assert not proxy.pending
