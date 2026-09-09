"""Network operations. Sensitive values remain in process memory only."""

from __future__ import annotations

from collections import Counter
from contextlib import asynccontextmanager, contextmanager
from functools import wraps
import inspect
from datetime import datetime, timezone
import ftplib
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path, PurePosixPath
import socket
import threading
import ssl
import time
from typing import Any, Iterator

import httpx
from icmplib import ping, traceroute
from netmiko import ConnectHandler
from netmiko.fortinet.fortinet_ssh import FortinetSSH

from .audit import record
from .auth import TargetAuth
from .read_policy import normalize_platform, render_read_query
from .sanitize import digest_text, redact


_WEAK_SSH_KEX = [
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
]
_SSH_CACHE_TTL_SECONDS = 120.0
_SSH_CACHE_MAX_ENTRIES = 8
_SSH_CAPTURE_MAX_BYTES = 2_000_000
_SSH_PAGE_CACHE: dict[tuple[Any, ...], tuple[float, str]] = {}
_SSH_CACHE_LOCK = threading.Lock()


class ReadOnlyFortinetSSH(FortinetSSH):
    """FortiOS session setup which never enters configuration or changes paging."""

    def session_preparation(self) -> None:
        data = self._test_channel_read(pattern=f"to accept|{self.prompt_pattern}")
        if "to accept" in data:
            self.write_channel("a\r")
            self._test_channel_read(pattern=self.prompt_pattern)
        self.set_base_prompt()

    def cleanup(self, command: str = "exit") -> None:
        # Closing Paramiko directly avoids FortinetSSH's persistent paging restore.
        return None


@contextmanager
def _known_hosts_file(auth: TargetAuth) -> Iterator[str]:
    auth.require_known_hosts()
    fd, path = tempfile.mkstemp(prefix="netops-known-hosts-", dir="/tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(auth.known_hosts)
        os.chmod(path, 0o600)
        yield path
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass



@contextmanager
def netmiko_connection(auth: TargetAuth, platform: str) -> Iterator[Any]:
    normalized = normalize_platform(platform)
    if normalized == "fortinet" and not auth.fortios_output_standard_verified:
        raise ValueError("FortiOS output standard must be independently verified before enrollment")
    with _known_hosts_file(auth) as known_hosts_path:
        connection_factory = ReadOnlyFortinetSSH if normalized == "fortinet" else ConnectHandler
        extra = {"disabled_algorithms": {"kex": _WEAK_SSH_KEX}} if normalized == "fortinet" else {}
        connection = connection_factory(
            device_type=normalized,
            host=auth.host,
            port=auth.port,
            username=auth.login,
            password=auth.password,
            conn_timeout=10,
            auth_timeout=12,
            banner_timeout=15,
            fast_cli=False,
            ssh_strict=True,
            system_host_keys=False,
            alt_host_keys=True,
            alt_key_file=known_hosts_path,
            **extra,
        )
        try:
            yield connection
        finally:
            connection.disconnect()


def _safe_error(exc: Exception, auth: TargetAuth) -> str:
    return redact(f"{type(exc).__name__}: {exc}", auth.secrets)



def _page_text(text: str, offset: int, max_bytes: int) -> dict[str, Any]:
    raw = text.encode("utf-8")
    offset = int(offset)
    max_bytes = min(max(int(max_bytes), 1_000), 48_000)
    if offset < 0 or offset > len(raw):
        raise ValueError("offset is outside the output")
    try:
        raw[:offset].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("offset is not a UTF-8 boundary; use next_offset") from exc
    end = min(offset + max_bytes, len(raw))
    while end > offset and end < len(raw) and raw[end] & 0xC0 == 0x80:
        end -= 1
    page = raw[offset:end].decode("utf-8")
    return {
        "total_bytes": len(raw),
        "offset": offset,
        "returned_bytes": end - offset,
        "next_offset": end if end < len(raw) else None,
        "complete": end == len(raw),
        "content_sha256": hashlib.sha256(raw).hexdigest(),
        "untrusted_device_output": page,
    }


def _audit_fields(arguments: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for name in ("port", "count", "max_hops", "offset", "max_bytes"):
        value = arguments.get(name)
        if isinstance(value, int) and not isinstance(value, bool):
            fields[name] = value
    for name in ("use_tls", "use_basic_auth", "acknowledge_unencrypted"):
        value = arguments.get(name)
        if isinstance(value, bool):
            fields[name if name != "acknowledge_unencrypted" else "plaintext_acknowledged"] = value
    if isinstance(arguments.get("oids"), list):
        fields["item_count"] = len(arguments["oids"])
    path = arguments.get("remote_path", arguments.get("path"))
    if isinstance(path, str):
        fields["path_sha256"] = digest_text(path)
    for name in ("query", "platform", "total_bytes", "returned_bytes", "pagination_source"):
        value = result.get(name)
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            fields[name] = value
    for name in ("content_sha256", "body_sha256", "remote_content_sha256"):
        value = result.get(name)
        if isinstance(value, str):
            fields["result_sha256"] = value
            break
    return fields


def _audit_device_call(function: Any) -> Any:
    signature = inspect.signature(function)
    event = function.__name__

    def write(auth: TargetAuth, arguments: dict[str, Any], result: dict[str, Any]) -> None:
        status = "ok" if result.get("ok") is True else "failed"
        record(event, target=auth.alias, status=status, **_audit_fields(arguments, result))

    if inspect.iscoroutinefunction(function):
        @wraps(function)
        async def async_wrapper(auth: TargetAuth, *args: Any, **kwargs: Any) -> dict[str, Any]:
            bound = signature.bind(auth, *args, **kwargs)
            try:
                result = await function(auth, *args, **kwargs)
            except Exception as exc:
                record(event, target=auth.alias, status="rejected", detail=type(exc).__name__)
                raise
            write(auth, dict(bound.arguments), result)
            return result
        return async_wrapper

    @wraps(function)
    def wrapper(auth: TargetAuth, *args: Any, **kwargs: Any) -> dict[str, Any]:
        bound = signature.bind(auth, *args, **kwargs)
        try:
            result = function(auth, *args, **kwargs)
        except Exception as exc:
            record(event, target=auth.alias, status="rejected", detail=type(exc).__name__)
            raise
        write(auth, dict(bound.arguments), result)
        return result
    return wrapper


def _ssh_cache_key(
    auth: TargetAuth, platform: str, query: str, parameters: dict[str, str] | None,
) -> tuple[Any, ...]:
    return (
        auth.alias, auth.host, auth.port, auth.login,
        platform, query, tuple(sorted((parameters or {}).items())),
    )


def _load_cached_ssh_output(key: tuple[Any, ...]) -> str | None:
    now = time.monotonic()
    with _SSH_CACHE_LOCK:
        for candidate, (expires, _) in list(_SSH_PAGE_CACHE.items()):
            if expires <= now:
                _SSH_PAGE_CACHE.pop(candidate, None)
        cached = _SSH_PAGE_CACHE.get(key)
        return cached[1] if cached else None


def _store_cached_ssh_output(key: tuple[Any, ...], output: str) -> None:
    with _SSH_CACHE_LOCK:
        if len(_SSH_PAGE_CACHE) >= _SSH_CACHE_MAX_ENTRIES:
            oldest = min(_SSH_PAGE_CACHE, key=lambda item: _SSH_PAGE_CACHE[item][0])
            _SSH_PAGE_CACHE.pop(oldest, None)
        _SSH_PAGE_CACHE[key] = (time.monotonic() + _SSH_CACHE_TTL_SECONDS, output)


@_audit_device_call
def ssh_read(
    auth: TargetAuth,
    platform: str,
    query: str,
    parameters: dict[str, str] | None,
    offset: int,
    max_bytes: int,
) -> dict[str, Any]:
    normalized, command = render_read_query(platform, query, parameters, auth.read_inventory)
    offset = int(offset)
    cache_key = _ssh_cache_key(auth, normalized, query, parameters)
    pagination_source = "fresh"
    if offset:
        cleaned = _load_cached_ssh_output(cache_key)
        if cleaned is None:
            raise ValueError("SSH pagination state expired; restart at offset 0")
        pagination_source = "cached"
    else:
        try:
            with netmiko_connection(auth, normalized) as connection:
                output = str(connection.send_command(command, read_timeout=60))
        except Exception as exc:
            return {
                "ok": False, "target": auth.alias, "platform": normalized,
                "query": query, "error": _safe_error(exc, auth),
            }
        cleaned = redact(output, auth.secrets)
        if len(cleaned.encode("utf-8")) > _SSH_CAPTURE_MAX_BYTES:
            return {
                "ok": False, "target": auth.alias, "platform": normalized,
                "query": query, "error": "SSH output exceeds the 2000000-byte safety cap",
            }
    page = _page_text(cleaned, offset, max_bytes)
    if page["next_offset"] is not None:
        _store_cached_ssh_output(cache_key, cleaned)
    else:
        with _SSH_CACHE_LOCK:
            _SSH_PAGE_CACHE.pop(cache_key, None)
    return {
        "ok": True, "target": auth.alias, "platform": normalized, "query": query,
        "pagination_source": pagination_source, **page,
    }


@_audit_device_call
def dns_probe(auth: TargetAuth) -> dict[str, Any]:
    started = time.monotonic()
    try:
        results = socket.getaddrinfo(auth.host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        return {"ok": False, "target": auth.alias, "error": _safe_error(exc, auth)}
    families = Counter("IPv6" if row[0] == socket.AF_INET6 else "IPv4" for row in results)
    addresses = sorted({str(row[4][0]) for row in results})
    return {
        "ok": True,
        "target": auth.alias,
        "answers": sum(families.values()),
        "families": dict(families),
        "untrusted_device_addresses": addresses,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
    }


@_audit_device_call
def tcp_probe(auth: TargetAuth, port: int, timeout: float) -> dict[str, Any]:
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    timeout = min(max(float(timeout), 0.2), 15.0)
    started = time.monotonic()
    try:
        with socket.create_connection((auth.host, port), timeout=timeout):
            pass
    except OSError as exc:
        return {
            "ok": False, "target": auth.alias, "port": port,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "error": _safe_error(exc, auth),
        }
    return {
        "ok": True, "target": auth.alias, "port": port,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
    }


@_audit_device_call
def icmp_probe(auth: TargetAuth, count: int) -> dict[str, Any]:
    count = min(max(int(count), 1), 8)
    try:
        result = ping(auth.host, count=count, interval=0.2, timeout=2, privileged=False)
    except Exception as exc:
        return {"ok": False, "target": auth.alias, "error": _safe_error(exc, auth)}
    return {
        "ok": bool(result.is_alive),
        "target": auth.alias,
        "packets_sent": result.packets_sent,
        "packets_received": result.packets_received,
        "packet_loss_percent": result.packet_loss * 100,
        "min_rtt_ms": result.min_rtt,
        "avg_rtt_ms": result.avg_rtt,
        "max_rtt_ms": result.max_rtt,
        "jitter_ms": result.jitter,
    }


@_audit_device_call
def route_trace(auth: TargetAuth, max_hops: int) -> dict[str, Any]:
    max_hops = min(max(int(max_hops), 1), 32)
    try:
        hops = traceroute(
            auth.host, count=1, interval=0.05, timeout=2,
            max_hops=max_hops, fast=True, privileged=False,
        )
    except Exception as exc:
        return {"ok": False, "target": auth.alias, "error": _safe_error(exc, auth)}
    return {
        "ok": bool(hops),
        "target": auth.alias,
        "hops": [
            {
                "distance": hop.distance,
                "address": hop.address,
                "responded": hop.packets_received > 0,
                "avg_rtt_ms": hop.avg_rtt,
            }
            for hop in hops
        ],
    }


def _name_tuple(entries: tuple[tuple[tuple[str, str], ...], ...]) -> list[dict[str, str]]:
    return [{key: value for key, value in group} for group in entries]


@_audit_device_call
def tls_probe(auth: TargetAuth, port: int, server_name: str | None) -> dict[str, Any]:
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    context = ssl.create_default_context()
    started = time.monotonic()
    try:
        with socket.create_connection((auth.host, port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=server_name or auth.host) as wrapped:
                cert = wrapped.getpeercert()
                der = wrapped.getpeercert(binary_form=True)
                cipher = wrapped.cipher()
                version = wrapped.version()
    except Exception as exc:
        return {"ok": False, "target": auth.alias, "port": port, "error": _safe_error(exc, auth)}
    not_after = cert.get("notAfter")
    days_remaining = None
    if isinstance(not_after, str):
        days_remaining = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
    return {
        "ok": True,
        "target": auth.alias,
        "port": port,
        "tls_version": version,
        "cipher": cipher[0] if cipher else None,
        "subject": redact(_name_tuple(cert.get("subject", ())), auth.secrets),
        "issuer": redact(_name_tuple(cert.get("issuer", ())), auth.secrets),
        "days_remaining": days_remaining,
        "certificate_sha256": hashlib.sha256(der).hexdigest(),
        "verified_by_system_trust": True,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
    }


@_audit_device_call
def https_get(
    auth: TargetAuth,
    path: str,
    port: int,
    use_basic_auth: bool,
    timeout: float,
    offset: int,
    max_bytes: int,
) -> dict[str, Any]:
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    path = auth.require_https_endpoint(path, port, use_basic_auth)
    url = f"https://{auth.host}:{port}{path}"
    credentials = (auth.login, auth.password) if use_basic_auth else None
    try:
        with httpx.Client(verify=True, timeout=min(max(timeout, 1), 30), follow_redirects=False) as client:
            response = client.get(url, auth=credentials)
    except Exception as exc:
        return {"ok": False, "target": auth.alias, "error": _safe_error(exc, auth)}
    content_type = response.headers.get("content-type", "")
    body = ""
    if "text" in content_type or "json" in content_type or not content_type:
        body = redact(response.text, auth.secrets)
    page = _page_text(body, offset, max_bytes)
    page["untrusted_device_body"] = page.pop("untrusted_device_output")
    return {
        "ok": response.is_success,
        "target": auth.alias,
        "status_code": response.status_code,
        "content_type": content_type.split(";", 1)[0],
        "content_length": len(response.content),
        "body_sha256": hashlib.sha256(response.content).hexdigest(),
        **page,
    }


@_audit_device_call
async def snmp_get(auth: TargetAuth, oids: list[str], port: int) -> dict[str, Any]:
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine,
        UdpTransportTarget, get_cmd,
    )

    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not oids or len(oids) > 20:
        raise ValueError("provide between 1 and 20 OIDs")
    if any(not oid or len(oid) > 200 for oid in oids):
        raise ValueError("invalid OID")
    engine = SnmpEngine()
    transport = await UdpTransportTarget.create((auth.host, port), timeout=2, retries=1)
    try:
        error_indication, error_status, error_index, var_binds = await get_cmd(
            engine,
            CommunityData(auth.password, mpModel=1),
            transport,
            ContextData(),
            *(ObjectType(ObjectIdentity(oid)) for oid in oids),
        )
    except Exception as exc:
        return {"ok": False, "target": auth.alias, "error": _safe_error(exc, auth)}
    finally:
        engine.close_dispatcher()
    if error_indication or error_status:
        failure = error_indication or error_status.prettyPrint()
        return {"ok": False, "target": auth.alias, "error": redact(failure, auth.secrets)}
    return {
        "ok": True,
        "target": auth.alias,
        "values": [
            {"oid": name.prettyPrint(), "value": redact(value.prettyPrint(), auth.secrets)}
            for name, value in var_binds
        ],
    }


@asynccontextmanager
async def _sftp_client(auth: TargetAuth):
    import asyncssh

    with _known_hosts_file(auth) as known_hosts_path:
        async with asyncssh.connect(
            auth.host,
            port=auth.port,
            username=auth.login,
            password=auth.password,
            client_keys=[],
            known_hosts=known_hosts_path,
            config=None,
            connect_timeout=10,
            login_timeout=15,
            keepalive_interval=15,
            keepalive_count_max=2,
        ) as connection:
            async with connection.start_sftp_client(sftp_version=3) as sftp:
                yield sftp


@_audit_device_call
async def sftp_stat(auth: TargetAuth, remote_path: str) -> dict[str, Any]:
    path = _safe_remote_path(auth, remote_path)
    try:
        async with _sftp_client(auth) as sftp:
            attributes = await sftp.stat(path)
    except Exception as exc:
        return {"ok": False, "target": auth.alias, "error": _safe_error(exc, auth)}
    size = int(attributes.size or 0)
    permissions = int(attributes.permissions or 0)
    modified = attributes.mtime
    return {
        "ok": True, "target": auth.alias, "path_sha256": digest_text(path),
        "size": size, "mode": oct(permissions & 0o7777),
        "modified_utc": datetime.fromtimestamp(modified, timezone.utc).isoformat() if modified is not None else None,
    }


@_audit_device_call
async def sftp_read_text(
    auth: TargetAuth, remote_path: str, offset: int, max_bytes: int,
) -> dict[str, Any]:
    path = _safe_remote_path(auth, remote_path)
    try:
        async with _sftp_client(auth) as sftp:
            attributes = await sftp.stat(path)
            if int(attributes.size or 0) > 2_000_000:
                raise ValueError("remote text file exceeds the 2000000-byte safety cap")
            async with sftp.open(path, "rb") as handle:
                raw = await handle.read(2_000_001)
    except Exception as exc:
        return {"ok": False, "target": auth.alias, "error": _safe_error(exc, auth)}
    if len(raw) > 2_000_000:
        return {"ok": False, "target": auth.alias, "error": "remote text file exceeds safety cap"}
    cleaned = redact(raw.decode("utf-8", "replace"), auth.secrets)
    page = _page_text(cleaned, offset, max_bytes)
    page["untrusted_device_content"] = page.pop("untrusted_device_output")
    return {
        "ok": True, "target": auth.alias, "path_sha256": digest_text(path),
        "remote_size": len(raw), "remote_content_sha256": hashlib.sha256(raw).hexdigest(), **page,
    }


def _safe_remote_path(auth: TargetAuth, remote_path: str) -> str:
    requested = PurePosixPath(remote_path)
    if (
        not requested.is_absolute() or "\x00" in remote_path or len(remote_path) > 2_000
        or ".." in requested.parts
    ):
        raise ValueError("remote path must be an absolute POSIX path")
    path = str(requested)
    if not any(
        path == root or path.startswith(root.rstrip("/") + "/")
        for root in auth.sftp_roots
    ):
        raise ValueError("remote path is outside the target SFTP allowlist")
    return path


TLS_PINS_PATH = Path("/etc/netops-helper/tls-pins.json")
TLS_CERT_DIR = Path("/etc/netops-helper/certs")
PLAIN_FTP_WARNING = (
    "WARNING: Plain FTP is unencrypted. Credentials and directory listing data "
    "are transmitted in plaintext."
)


def _ftps_context(alias: str) -> tuple[ssl.SSLContext, str | None]:
    try:
        configured = json.loads(TLS_PINS_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context, None
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("FTPS pin configuration is invalid") from exc
    entry = configured.get(alias)
    if entry is None:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context, None
    if not isinstance(entry, dict):
        raise RuntimeError("FTPS pin entry is invalid")
    digest = str(entry.get("sha256", "")).lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise RuntimeError("FTPS pin digest is invalid")
    certificate = Path(str(entry.get("certificate", ""))).resolve()
    certificate_root = TLS_CERT_DIR.resolve()
    if certificate_root not in certificate.parents or not certificate.is_file():
        raise RuntimeError("FTPS pin certificate is unavailable")
    context = ssl.create_default_context(cafile=str(certificate))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    if hasattr(ssl, "VERIFY_X509_PARTIAL_CHAIN"):
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return context, digest


@_audit_device_call
def ftp_list(
    auth: TargetAuth,
    remote_path: str,
    use_tls: bool,
    port: int,
    acknowledge_unencrypted: bool = False,
) -> dict[str, Any]:
    remote_path = _safe_remote_path(auth, remote_path)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not use_tls and not acknowledge_unencrypted:
        raise ValueError(
            PLAIN_FTP_WARNING
            + " Set acknowledge_unencrypted=true only after explicit user approval."
        )
    pin_digest: str | None = None
    security_warning: str | None = None
    if use_tls:
        context, pin_digest = _ftps_context(auth.alias)
        client: ftplib.FTP = ftplib.FTP_TLS(timeout=30, context=context)
    else:
        security_warning = PLAIN_FTP_WARNING
        client = ftplib.FTP(timeout=30)
    stage = "connect"
    try:
        client.connect(auth.host, port)
        if isinstance(client, ftplib.FTP_TLS):
            stage = "tls_handshake"
            client.auth()
            if pin_digest is not None:
                stage = "certificate_pin"
                peer = client.sock.getpeercert(binary_form=True)
                actual = hashlib.sha256(peer or b"").hexdigest()
                if not peer or not hmac.compare_digest(actual, pin_digest):
                    raise ssl.SSLCertVerificationError("pinned FTPS certificate mismatch")
            stage = "login_over_tls"
            client.login(auth.login, auth.password)
            stage = "protect_data_channel"
            client.prot_p()
        else:
            stage = "plain_login"
            client.login(auth.login, auth.password)
        stage = "directory_list"
        names = client.nlst(remote_path)
        stage = "quit"
        client.quit()
    except Exception as exc:
        try:
            client.close()
        except Exception:
            pass
        return {
            "ok": False,
            "target": auth.alias,
            "tls": use_tls,
            "transport_encrypted": use_tls,
            "plaintext_acknowledged": not use_tls and acknowledge_unencrypted,
            "security_warning": security_warning,
            "certificate_pinned": pin_digest is not None,
            "failure_stage": stage,
            "error_type": type(exc).__name__,
            "error": _safe_error(exc, auth),
        }
    return {
        "ok": True, "target": auth.alias, "tls": use_tls,
        "transport_encrypted": use_tls,
        "plaintext_acknowledged": not use_tls and acknowledge_unencrypted,
        "security_warning": security_warning,
        "certificate_pinned": pin_digest is not None,
        "entries": [redact(PurePosixPath(name).name, auth.secrets) for name in names[:500]],
        "truncated": len(names) > 500,
    }
