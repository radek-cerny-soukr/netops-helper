#!/usr/bin/env python3
"""Dependency-free phase-1 security contract tests."""

from __future__ import annotations

from base64 import urlsafe_b64encode
import importlib.util
import json
from pathlib import Path

from netops_helper.auth import TargetAuth
from netops_helper.read_policy import render_read_query
from netops_helper.sanitize import redact


def must_fail(function, *args, **kwargs) -> None:
    try: function(*args, **kwargs)
    except Exception: return
    raise AssertionError(f"{function.__name__} unexpectedly succeeded")


def main() -> int:
    raw=json.dumps({
        "alias":"device-a","host":"192.0.2.10","port":22,"login":"operator",
        "password":"correct horse battery staple","known_hosts":"test-key",
        "account_role":"read-only","read_inventory":{"interfaces":["port3"]},
    }).encode()
    context=urlsafe_b64encode(raw).decode().rstrip("=")
    auth=TargetAuth.decode("device-a",context)
    assert auth.secrets == ("correct horse battery staple",)
    must_fail(TargetAuth.decode,"device-b",context)

    cleaned=redact(
        "peer 192.0.2.10 aa:bb:cc:dd:ee:ff username=operator password=hunter2 ENC blob",
        secrets=("hunter2",),
    )
    for visible in ("192.0.2.10","aa:bb:cc:dd:ee:ff","operator"): assert visible in cleaned
    for hidden in ("hunter2","ENC blob"): assert hidden not in cleaned

    _,command=render_read_query("fortios","interface_details",{"interface":"port3"},{"interfaces":("port3",)})
    assert command == "diagnose netlink interface list port3"
    must_fail(render_read_query,"fortios","interface_details",{"interface":"port4"},{"interfaces":("port3",)})
    must_fail(render_read_query,"fortios","config system interface",{}, {})

    proxy_path=Path(__file__).parents[1]/"scripts"/"remote_mcp_proxy.py"
    import sys; sys.path.insert(0,str(proxy_path.parent))
    spec=importlib.util.spec_from_file_location("remote_mcp_proxy",proxy_path)
    module=importlib.util.module_from_spec(spec); assert spec.loader is not None; spec.loader.exec_module(module)
    proxy=module.Proxy(); proxy.pending[9]="tools/call"; proxy.response_secrets[9]=("secret-value",)
    response={"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text","text":"Sep 9 10:23:45 ip=192.0.2.10 serial=FGABCDEF123456 username=operator secret-value"}]}}
    transformed=json.loads(proxy.response(json.dumps(response).encode()))
    output=transformed["result"]["content"][0]["text"]
    for visible in ("10:23:45","192.0.2.10","FGABCDEF123456","operator"): assert visible in output
    assert "secret-value" not in output and output.startswith("UNTRUSTED DEVICE DATA")

    root=Path(__file__).parents[1]
    assert not (root/"plugin").exists()
    source="\n".join(path.read_text().lower() for path in (root/"src/netops_helper").glob("*.py"))
    for forbidden in ("prepare_", "apply_", "cancel_change", "sftp_upload", "send_command_timing", "posix_rename", "save_config", "config_mode"):
        assert forbidden not in source
    print("security_unit_tests=passed")
    return 0


if __name__ == "__main__": raise SystemExit(main())
