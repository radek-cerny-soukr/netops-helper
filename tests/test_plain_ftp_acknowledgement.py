from __future__ import annotations

import pytest

from netops_helper.auth import TargetAuth
import netops_helper.engine as engine


def target_auth() -> TargetAuth:
    return TargetAuth(
        "legacy-device", "host.invalid", 21, "account", "credential", "public-key", ("/safe",),
    )


def test_plain_ftp_is_rejected_before_client_creation_without_acknowledgement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_client(*args, **kwargs):
        raise AssertionError("plain FTP client must not be created without acknowledgement")

    monkeypatch.setattr(engine.ftplib, "FTP", forbidden_client)

    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    with pytest.raises(ValueError, match="Plain FTP is unencrypted"):
        engine.ftp_list(target_auth(), "/safe", use_tls=False, port=21)


class FakePlainFTP:
    def __init__(self, timeout: int) -> None:
        assert timeout == 30
        self.connected = False
        self.logged_in = False
        self.closed = False

    def connect(self, host: str, port: int) -> None:
        assert host == "host.invalid" and port == 21
        self.connected = True

    def login(self, login: str, password: str) -> None:
        assert self.connected
        assert login == "account" and password == "credential"
        self.logged_in = True

    def nlst(self, remote_path: str) -> list[str]:
        assert self.logged_in and remote_path == "/safe"
        return ["/safe-file.txt"]

    def quit(self) -> None:
        self.closed = True

    def close(self) -> None:
        self.closed = True


def test_acknowledged_plain_ftp_returns_permanent_unencrypted_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(engine.ftplib, "FTP", FakePlainFTP)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)

    result = engine.ftp_list(
        target_auth(), "/safe", use_tls=False, port=21, acknowledge_unencrypted=True,
    )

    assert result["ok"]
    assert result["tls"] is False
    assert result["transport_encrypted"] is False
    assert result["plaintext_acknowledged"] is True
    assert result["security_warning"] == engine.PLAIN_FTP_WARNING
    assert "credentials" in result["security_warning"].lower()
    assert "directory listing" in result["security_warning"].lower()
    assert result["entries"] == ["safe-file.txt"]
