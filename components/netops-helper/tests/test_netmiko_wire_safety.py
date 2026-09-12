"""Wire-level regression pinning what upstream Netmiko drivers send for every non-FortiOS profile."""

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
from netops_helper.query_catalog import READ_QUERIES


LOOPBACK = socket.inet_ntoa(bytes((127, 0, 0, 1)))
OUTPUT_MARKER = "wire-test output marker"
CLEANUP_COMMANDS = frozenset({"exit"})
FORBIDDEN_COMMANDS = re.compile(
    r"^(?:conf(?:igure)?(?:\s|$)|config(?:\s|$)|enable(?:\s|$)|write(?:\s|$)|copy(?:\s|$)|reload(?:\s|$)"
    r"|delete(?:\s|$)|erase(?:\s|$)|commit(?:\s|$)|edit(?:\s|$)|clear(?:\s|$)|debug(?:\s|$)"
    r"|no\s|save(?:\s|$)|set\s(?!cli\s)|unset\s|create(?:\s|$)|run(?:\s|$)|request(?:\s|$)|sudo(?:\s|$))",
    re.IGNORECASE,
)
PLATFORMS = {
    "cisco_ios": ("switch#", ["terminal width 511", "terminal length 0"], {}),
    "cisco_xe": ("switch#", ["terminal width 511", "terminal length 0"], {}),
    "cisco_nxos": ("switch#", ["terminal width 511", "terminal length 0"], {}),
    "arista_eos": (
        "switch#",
        ["terminal width 511", "terminal length 0"],
        {"terminal width 511": "Width set to 511 columns.", "terminal length 0": "Pagination disabled."},
    ),
    "juniper_junos": (
        "reader@router>",
        ["set cli screen-width 511", "set cli complete-on-space off", "set cli screen-length 0"],
        {
            "set cli screen-width 511": "Screen width set to 511",
            "set cli complete-on-space off": "Disabling complete-on-space",
            "set cli screen-length 0": "Screen length set to 0",
        },
    ),
    "juniper_junos_els": (
        "reader@router>",
        ["set cli screen-width 511", "set cli complete-on-space off", "set cli screen-length 0"],
        {
            "set cli screen-width 511": "Screen width set to 511",
            "set cli complete-on-space off": "Disabling complete-on-space",
            "set cli screen-length 0": "Screen length set to 0",
        },
    ),
    "extreme_exos": ("Switch.1 #", ["disable clipaging", "disable cli prompting"], {}),
    "linux": ("reader@host:~$", [], {}),
}


def _plain_query(platform: str) -> tuple[str, str]:
    for name, query in READ_QUERIES[platform].items():
        if not query.slots and not query.high_volume:
            return name, query.command
    raise AssertionError(f"no slot-free query for {platform}")


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

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self.shell_requested.set()
        return True


class _DeviceSSHServer:
    def __init__(self, prompt: str, query: str, replies: dict[str, str]) -> None:
        self.username = "reader"
        self.password = "wire-test-password"
        self.prompt = prompt
        self.query = query
        self.replies = replies
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
        self._thread = threading.Thread(target=self._serve, name="netmiko-wire-safety-server", daemon=True)
        self._thread.start()

    @property
    def known_hosts(self) -> str:
        return f"[{LOOPBACK}]:{self.port} {self.host_key.get_name()} {self.host_key.get_base64()}\n"

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
        match = re.search(rb"[\r\n]", buffer)
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
            channel.sendall(("\r\n" + self.prompt + " ").encode("utf-8"))
            return
        self.commands.append(command)
        body = self.replies.get(command)
        if command == self.query:
            body = OUTPUT_MARKER
        text = command + "\r\n" + (body + "\r\n" if body else "") + self.prompt + " "
        channel.sendall(text.encode("utf-8"))

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
            channel.sendall((self.prompt + " ").encode("utf-8"))
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
            raise TimeoutError("fake device SSH server did not stop")


@contextmanager
def _device_server(prompt: str, query: str, replies: dict[str, str]) -> Iterator[_DeviceSSHServer]:
    server = _DeviceSSHServer(prompt, query, replies)
    try:
        yield server
    finally:
        server.close()


def _target(server: _DeviceSSHServer, platform: str, query_name: str) -> TargetAuth:
    return TargetAuth(
        alias="netmiko-wire-test",
        host=LOOPBACK,
        port=server.port,
        login=server.username,
        password=server.password,
        known_hosts=server.known_hosts,
        read_inventory={},
        account_role="read-only",
        ssh_platform=platform,
        enabled_queries=(query_name,),
        egress=EgressPolicy(addresses=(LOOPBACK,)),
    )


@pytest.mark.parametrize("platform", sorted(PLATFORMS))
def test_upstream_driver_sends_only_pinned_session_setup_and_the_enrolled_query(
    monkeypatch: pytest.MonkeyPatch, platform: str,
) -> None:
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    engine._SSH_PAGE_CACHE.clear()
    prompt, expected_setup, replies = PLATFORMS[platform]
    query_name, command = _plain_query(platform)

    with _device_server(prompt, command, replies) as server:
        result = engine.ssh_read(_target(server, platform, query_name), platform, query_name, {}, 0, 16_000)

    assert server.errors == []
    assert result["ok"] is True, result
    assert OUTPUT_MARKER in result["untrusted_device_output"]
    assert server.commands.count(command) == 1
    setup = server.commands[: server.commands.index(command)]
    assert setup == expected_setup, server.commands
    trailing = server.commands[server.commands.index(command) + 1:]
    assert set(trailing) <= CLEANUP_COMMANDS, server.commands
    assert not any(FORBIDDEN_COMMANDS.match(item) for item in server.commands), server.commands
