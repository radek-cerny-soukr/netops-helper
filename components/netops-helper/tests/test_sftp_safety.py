#!/usr/bin/env python3
"""Tests for read-only SFTP path confinement (pytest and direct execution)."""

from __future__ import annotations

from netops_helper.auth import TargetAuth
import netops_helper.engine as engine


def test_safe_remote_path_confinement() -> None:
    auth = TargetAuth(
        "device-a", "host.invalid", 22, "account", "credential", "public-key", ("/safe",),
    )
    assert engine._safe_remote_path(auth, "/safe/config") == "/safe/config"
    for unsafe in ("/etc/passwd", "/safe/../etc/passwd", "/", "relative/path"):
        try:
            engine._safe_remote_path(auth, unsafe)
        except ValueError:
            pass
        else:
            raise AssertionError(f"unsafe SFTP path accepted: {unsafe}")
    deny_all = TargetAuth("device-a", "host.invalid", 22, "account", "credential", "public-key")
    try:
        engine._safe_remote_path(deny_all, "/safe/config")
    except ValueError:
        pass
    else:
        raise AssertionError("missing SFTP policy did not fail closed")


def main() -> int:
    test_safe_remote_path_confinement()
    print("sftp_safety_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
