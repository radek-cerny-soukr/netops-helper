from __future__ import annotations

from contextlib import contextmanager

import pytest

from netops_helper.auth import TargetAuth
import netops_helper.engine as engine


def auth(*, fortios_verified: bool = True) -> TargetAuth:
    return TargetAuth(
        "device-a", "host.invalid", 22, "reader", "credential", "known-key",
        ("/safe",), (("/status", 443, False),), {"interfaces": ("port3",)}, "read-only",
        fortios_verified,
    )


def test_fortios_connection_uses_read_only_driver_and_disables_sha1_kex(monkeypatch) -> None:
    captured = {}

    class FakeConnection:
        def __init__(self, **kwargs):
            captured.update(kwargs)
        def disconnect(self):
            captured["disconnected"] = True

    monkeypatch.setattr(engine, "ReadOnlyFortinetSSH", FakeConnection)
    with engine.netmiko_connection(auth(), "fortios"):
        pass
    assert captured["disabled_algorithms"]["kex"] == engine._WEAK_SSH_KEX
    assert all(name.endswith("sha1") for name in engine._WEAK_SSH_KEX)
    assert captured["disconnected"] is True


def test_fortios_connection_requires_verified_output_standard(monkeypatch) -> None:
    monkeypatch.setattr(
        engine, "ReadOnlyFortinetSSH",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("connection must not open")),
    )
    with pytest.raises(ValueError, match="output standard"):
        with engine.netmiko_connection(auth(fortios_verified=False), "fortios"):
            pass


def test_ssh_continuation_uses_cache_without_second_login(monkeypatch) -> None:
    calls = []

    class FakeConnection:
        def send_command(self, command, read_timeout):
            calls.append(command)
            return "x" * 1500

    @contextmanager
    def fake_connection(*args, **kwargs):
        yield FakeConnection()

    monkeypatch.setattr(engine, "netmiko_connection", fake_connection)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    engine._SSH_PAGE_CACHE.clear()
    first = engine.ssh_read(auth(), "fortios", "interface_details", {"interface": "port3"}, 0, 1000)
    second = engine.ssh_read(
        auth(), "fortios", "interface_details", {"interface": "port3"}, first["next_offset"], 1000,
    )
    assert first["pagination_source"] == "fresh"
    assert second["pagination_source"] == "cached"
    assert second["complete"] is True
    assert len(calls) == 1


def test_every_device_function_has_audit_wrapper() -> None:
    names = (
        "dns_probe", "tcp_probe", "icmp_probe", "route_trace", "tls_probe", "https_get",
        "ssh_read", "snmp_get", "sftp_stat", "sftp_read_text", "ftp_list",
    )
    assert all(hasattr(getattr(engine, name), "__wrapped__") for name in names)


def test_https_and_ftp_paths_fail_closed(monkeypatch) -> None:
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    with pytest.raises(ValueError):
        engine.ftp_list(auth(), "/outside", True, 21)
    with pytest.raises(Exception, match="HTTPS endpoint"):
        engine.https_get(auth(), "/action?reboot=1", 443, True, 5, 0, 1000)
