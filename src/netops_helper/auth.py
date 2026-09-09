"""Ephemeral credentials and read-only target policy injected by the local MCP proxy."""

from __future__ import annotations

from base64 import urlsafe_b64decode
from dataclasses import dataclass, field
import ipaddress
import json
from pathlib import PurePosixPath


class AuthenticationContextError(ValueError):
    """Raised when the proxy-provided authentication envelope is invalid."""


def _valid_https_path(path: str) -> bool:
    return (
        path.startswith("/")
        and not path.startswith("//")
        and "://" not in path
        and "#" not in path
        and "\x00" not in path
        and len(path) <= 2_000
        and not any(ord(char) < 32 for char in path)
    )


@dataclass(frozen=True, slots=True)
class TargetAuth:
    alias: str
    host: str
    port: int
    login: str
    password: str
    known_hosts: str
    sftp_roots: tuple[str, ...] = ()
    https_endpoints: tuple[tuple[str, int, bool], ...] = ()
    read_inventory: dict[str, tuple[str, ...]] = field(default_factory=dict)
    account_role: str = "read-only"
    fortios_output_standard_verified: bool = False

    @classmethod
    def decode(cls, expected_alias: str, context: str) -> "TargetAuth":
        try:
            padding = "=" * (-len(context) % 4)
            raw = urlsafe_b64decode((context + padding).encode("ascii"))
            data = json.loads(raw.decode("utf-8"))
            roots = data.get("sftp_roots", [])
            if not isinstance(roots, list) or not all(isinstance(root, str) for root in roots):
                raise TypeError("sftp_roots must be a list of strings")
            normalized_roots = tuple(dict.fromkeys(str(PurePosixPath(root)) for root in roots))
            if any(
                not root.startswith("/") or root == "/" or "\x00" in root
                or ".." in PurePosixPath(root).parts or len(root) > 2_000
                for root in normalized_roots
            ):
                raise ValueError("sftp_roots contains an unsafe root")

            https_endpoints = data.get("https_endpoints", [])
            if not isinstance(https_endpoints, list) or len(https_endpoints) > 256:
                raise ValueError("https_endpoints has an invalid structure")
            normalized_endpoints: list[tuple[str, int, bool]] = []
            for endpoint in https_endpoints:
                if not isinstance(endpoint, dict) or set(endpoint) != {"path", "port", "use_basic_auth"}:
                    raise ValueError("HTTPS endpoint must contain path, port, and use_basic_auth")
                path = endpoint["path"]
                port = endpoint["port"]
                use_basic_auth = endpoint["use_basic_auth"]
                if (
                    not isinstance(path, str) or not _valid_https_path(path)
                    or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535
                    or not isinstance(use_basic_auth, bool)
                ):
                    raise ValueError("https_endpoints contains an unsafe endpoint")
                normalized_endpoints.append((path, port, use_basic_auth))
            normalized_https_endpoints = tuple(dict.fromkeys(normalized_endpoints))

            inventory = data.get("read_inventory", {})
            if not isinstance(inventory, dict) or any(
                key not in {"interfaces", "services", "addresses"}
                or not isinstance(values, list)
                or not all(isinstance(value, str) for value in values)
                for key, values in inventory.items()
            ):
                raise TypeError("read_inventory has an invalid structure")
            normalized_inventory: dict[str, tuple[str, ...]] = {}
            for key, values in inventory.items():
                if len(values) > 256:
                    raise ValueError("read_inventory category is too large")
                clean = []
                for value in values:
                    if not value or len(value) > 128 or any(ord(char) < 32 for char in value):
                        raise ValueError("read_inventory contains an unsafe value")
                    clean.append(str(ipaddress.ip_address(value)) if key == "addresses" else value)
                normalized_inventory[key] = tuple(dict.fromkeys(clean))

            result = cls(
                alias=str(data["alias"]),
                host=str(data["host"]),
                port=int(data.get("port", 22)),
                login=str(data["login"]),
                password=str(data["password"]),
                known_hosts=str(data.get("known_hosts", "")),
                sftp_roots=normalized_roots,
                https_endpoints=normalized_https_endpoints,
                read_inventory=normalized_inventory,
                account_role=str(data.get("account_role", "")),
                fortios_output_standard_verified=(
                    data.get("fortios_output_standard_verified", False) is True
                ),
            )
        except (KeyError, TypeError, ValueError, UnicodeError) as exc:
            raise AuthenticationContextError("invalid ephemeral authentication context") from exc
        if result.alias != expected_alias:
            raise AuthenticationContextError("target alias does not match authentication context")
        if not result.host or not result.login or not result.password:
            raise AuthenticationContextError("authentication context has empty required fields")
        if not 1 <= result.port <= 65535:
            raise AuthenticationContextError("authentication context has invalid port")
        if result.account_role != "read-only":
            raise AuthenticationContextError("target is not explicitly enrolled as a read-only account")
        return result

    def require_known_hosts(self) -> None:
        if not self.known_hosts.strip():
            raise AuthenticationContextError("verified SSH host keys are unavailable")

    def require_https_endpoint(self, path: str, port: int, use_basic_auth: bool) -> str:
        endpoint = (path, port, use_basic_auth)
        if not _valid_https_path(path) or endpoint not in self.https_endpoints:
            raise AuthenticationContextError("HTTPS endpoint is outside the target allowlist")
        return path

    @property
    def secrets(self) -> tuple[str, ...]:
        """Only credentials are secrets; diagnostic identifiers must remain observable."""
        return (self.password,) if self.password else ()
