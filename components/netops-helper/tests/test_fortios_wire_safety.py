"""Wire-level FortiOS read-only regression using a real Paramiko SSH server."""

from __future__ import annotations

from contextlib import contextmanager
import importlib.util
import os
import re
import socket
import threading
from typing import Iterator

import pytest


_REQUIRE_RUNTIME = os.environ.get("NETOPS_REQUIRE_RUNTIME_TESTS") == "1"
_REQUIRED_MODULES = ("httpx", "icmplib", "netmiko", "paramiko")
_MISSING_RUNTIME = tuple(
    name for name in _REQUIRED_MODULES if importlib.util.find_spec(name) is None
)
if _MISSING_RUNTIME:
    message = "project runtime dependencies are missing: " + ", ".join(_MISSING_RUNTIME)
    if _REQUIRE_RUNTIME:
        raise RuntimeError(message)
    pytest.skip(message, allow_module_level=True)

import paramiko

from netops_helper.auth import EgressPolicy, TargetAuth
import netops_helper.engine as engine


LOOPBACK = socket.inet_ntoa(bytes((127, 0, 0, 1)))
DIAGNOSTIC_QUERY = "diagnose netlink interface list port3"
PROMPT = "FGT #"
OUTPUT_MARKER = "port3 wire-test link is up"
FORBIDDEN_MUTATING_COMMANDS = re.compile(
    r"^(?:config|edit|set|unset|next|end|save|commit|write|delete|execute)(?:\s|$)",
    re.IGNORECASE | re.MULTILINE,
)
FORBIDDEN_PAGING_FRAGMENTS = (
    "config system console",
    "set output standard",
    "set output more",
)


class _ServerInterface(paramiko.ServerInterface):
    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.shell_requested = threading.Event()

    def check_auth_password(self, username: str, password: str) -> int:
        if username == self.username and password == self.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self.shell_requested.set()
        return True


class _FortiOSSSHServer:
    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.host_key = paramiko.RSAKey.generate(2048)
        self.client_channel_bytes = bytearray()
        self.commands: list[str] = []
        self.errors: list[BaseException] = []
        self._stop = threading.Event()
        self._transport: paramiko.Transport | None = None
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((LOOPBACK, 0))
        self._listener.listen(1)
        self._listener.settimeout(0.2)
        self.port = int(self._listener.getsockname()[1])
        self._thread = threading.Thread(
            target=self._serve,
            name="fortios-wire-safety-server",
            daemon=True,
        )
        self._thread.start()

    @property
    def known_hosts(self) -> str:
        return (
            f"[{LOOPBACK}]:{self.port} {self.host_key.get_name()} "
            f"{self.host_key.get_base64()}\n"
        )

    def _accept(self) -> socket.socket | None:
        while not self._stop.is_set():
            try:
                connection, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return None
                raise
            connection.settimeout(10)
            return connection
        return None

    @staticmethod
    def _pop_line(buffer: bytes) -> tuple[bytes | None, bytes]:
        match = re.search(br"[\r\n]", buffer)
        if match is None:
            return None, buffer
        line = buffer[: match.start()]
        end = match.end()
        while end < len(buffer) and buffer[end] in (10, 13):
            end += 1
        return line, buffer[end:]

    def _reply(self, channel: paramiko.Channel, line: bytes) -> None:
        command = line.decode("utf-8", "strict").strip()
        if not command:
            channel.sendall(("\r\n" + PROMPT).encode("ascii"))
            return
        self.commands.append(command)
        channel.sendall((command + "\r\n").encode("utf-8"))
        if command == DIAGNOSTIC_QUERY:
            channel.sendall((OUTPUT_MARKER + "\r\n" + PROMPT).encode("utf-8"))
        else:
            channel.sendall(("Unknown command\r\n" + PROMPT).encode("ascii"))

    def _serve(self) -> None:
        connection: socket.socket | None = None
        channel: paramiko.Channel | None = None
        try:
            connection = self._accept()
            if connection is None:
                return
            server = _ServerInterface(self.username, self.password)
            transport = paramiko.Transport(connection)
            self._transport = transport
            transport.add_server_key(self.host_key)
            transport.start_server(server=server)
            channel = transport.accept(10)
            if channel is None:
                raise TimeoutError("SSH client did not open a session channel")
            if not server.shell_requested.wait(5):
                raise TimeoutError("SSH client did not request an interactive shell")
            channel.settimeout(0.2)
            channel.sendall(PROMPT.encode("ascii"))
            pending = b""
            while not self._stop.is_set() and transport.is_active():
                try:
                    chunk = channel.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                self.client_channel_bytes.extend(chunk)
                pending += chunk
                while True:
                    line, pending = self._pop_line(pending)
                    if line is None:
                        break
                    self._reply(channel, line)
        except BaseException as exc:
            if not self._stop.is_set():
                self.errors.append(exc)
        finally:
            if channel is not None:
                channel.close()
            if self._transport is not None:
                self._transport.close()
            if connection is not None:
                connection.close()

    def close(self) -> None:
        self._stop.set()
        if self._transport is not None:
            self._transport.close()
        self._listener.close()
        self._thread.join(5)
        if self._thread.is_alive():
            raise TimeoutError("fake FortiOS SSH server did not stop")


@contextmanager
def _fortios_server() -> Iterator[_FortiOSSSHServer]:
    server = _FortiOSSSHServer("reader", "wire-test-password")
    try:
        yield server
    finally:
        server.close()


def _target(server: _FortiOSSSHServer) -> TargetAuth:
    return TargetAuth(
        alias="fortios-wire-test",
        host=LOOPBACK,
        port=server.port,
        login=server.username,
        password=server.password,
        known_hosts=server.known_hosts,
        read_inventory={"interfaces": ("port3",)},
        account_role="read-only",
        fortios_output_standard_verified=True,
        ssh_platform="fortinet",
        enabled_queries=("interface_details",),
        egress=EgressPolicy(addresses=(LOOPBACK,)),
    )


def test_read_only_fortios_driver_sends_only_enrolled_diagnostic_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise real Netmiko/Paramiko transport and inspect received channel bytes."""
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    engine._SSH_PAGE_CACHE.clear()

    with _fortios_server() as server:
        result = engine.ssh_read(
            _target(server),
            "fortios",
            "interface_details",
            {"interface": "port3"},
            0,
            16_000,
        )

    assert server.errors == []
    assert result["ok"] is True, result
    assert OUTPUT_MARKER in result["untrusted_device_output"]

    # Empty prompt-discovery newlines are harmless; every actual command is captured here.
    assert server.commands == [DIAGNOSTIC_QUERY]
    wire_text = bytes(server.client_channel_bytes).decode("utf-8", "strict")
    assert DIAGNOSTIC_QUERY in wire_text
    assert not FORBIDDEN_MUTATING_COMMANDS.search(wire_text)
    assert all(fragment not in wire_text.lower() for fragment in FORBIDDEN_PAGING_FRAGMENTS)
