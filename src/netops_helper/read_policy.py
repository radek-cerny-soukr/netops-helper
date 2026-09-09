"""Typed, inventory-bound templates for read-only troubleshooting queries."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from string import Formatter
from typing import Mapping


PLATFORM_MAP = {
    "linux": "linux",
    "fortinet": "fortinet",
    "fortios": "fortinet",
    "extreme_exos": "extreme_exos",
    "cisco_ios": "cisco_ios",
    "cisco_xe": "cisco_xe",
    "arista_eos": "arista_eos",
    "juniper_junos": "juniper_junos",
}


@dataclass(frozen=True, slots=True)
class Slot:
    inventory: str
    kind: str


@dataclass(frozen=True, slots=True)
class Query:
    command: str
    slots: Mapping[str, Slot]


NO_SLOTS: Mapping[str, Slot] = {}
INTERFACE = {"interface": Slot("interfaces", "interface")}
SERVICE = {"service": Slot("services", "service")}
ADDRESS = {"address": Slot("addresses", "address")}


READ_QUERIES: dict[str, dict[str, Query]] = {
    "linux": {
        "hostname": Query("hostname", NO_SLOTS),
        "kernel": Query("uname -a", NO_SLOTS),
        "uptime": Query("uptime", NO_SLOTS),
        "filesystems": Query("df -h", NO_SLOTS),
        "memory": Query("free -m", NO_SLOTS),
        "links": Query("ip -brief link", NO_SLOTS),
        "addresses": Query("ip -brief address", NO_SLOTS),
        "routes": Query("ip route show", NO_SLOTS),
        "sockets": Query("ss -lntup", NO_SLOTS),
        "running_services": Query("systemctl --no-pager --state=running --type=service", NO_SLOTS),
        "interface_addresses": Query("ip -brief address show dev {interface}", INTERFACE),
        "interface_link": Query("ip -details link show dev {interface}", INTERFACE),
        "service_status": Query("systemctl --no-pager --full status {service}", SERVICE),
        "service_logs_recent": Query("journalctl --no-pager -u {service} --since -1h", SERVICE),
    },
    "fortinet": {
        "system_status": Query("get system status", NO_SLOTS),
        "performance": Query("get system performance status", NO_SLOTS),
        "ha_status": Query("get system ha status", NO_SLOTS),
        "routing_table": Query("get router info routing-table all", NO_SLOTS),
        "sdwan_health": Query("diagnose sys sdwan health-check", NO_SLOTS),
        "interface_details": Query("diagnose netlink interface list {interface}", INTERFACE),
        "route_lookup": Query("get router info routing-table details {address}", ADDRESS),
    },
    "extreme_exos": {
        "switch": Query("show switch", NO_SLOTS),
        "version": Query("show version", NO_SLOTS),
        "ports": Query("show ports no-refresh", NO_SLOTS),
        "route_summary": Query("show iproute summary", NO_SLOTS),
    },
    "cisco_ios": {
        "version": Query("show version", NO_SLOTS),
        "clock": Query("show clock", NO_SLOTS),
        "interfaces": Query("show interfaces status", NO_SLOTS),
        "ip_interfaces": Query("show ip interface brief", NO_SLOTS),
        "ipv6_interfaces": Query("show ipv6 interface brief", NO_SLOTS),
        "route_summary": Query("show ip route summary", NO_SLOTS),
        "cpu": Query("show processes cpu", NO_SLOTS),
        "memory": Query("show processes memory", NO_SLOTS),
        "interface_details": Query("show interfaces {interface}", INTERFACE),
        "route_lookup": Query("show ip route {address}", ADDRESS),
    },
    "cisco_xe": {
        "version": Query("show version", NO_SLOTS),
        "clock": Query("show clock", NO_SLOTS),
        "interfaces": Query("show interfaces status", NO_SLOTS),
        "ip_interfaces": Query("show ip interface brief", NO_SLOTS),
        "ipv6_interfaces": Query("show ipv6 interface brief", NO_SLOTS),
        "route_summary": Query("show ip route summary", NO_SLOTS),
        "cpu": Query("show processes cpu", NO_SLOTS),
        "memory": Query("show processes memory", NO_SLOTS),
        "interface_details": Query("show interfaces {interface}", INTERFACE),
        "route_lookup": Query("show ip route {address}", ADDRESS),
    },
    "arista_eos": {
        "version": Query("show version", NO_SLOTS),
        "clock": Query("show clock", NO_SLOTS),
        "interfaces": Query("show interfaces status", NO_SLOTS),
        "ip_interfaces": Query("show ip interface brief", NO_SLOTS),
        "ipv6_interfaces": Query("show ipv6 interface brief", NO_SLOTS),
        "route_summary": Query("show ip route summary", NO_SLOTS),
        "processes": Query("show processes top once", NO_SLOTS),
        "interface_details": Query("show interfaces {interface}", INTERFACE),
        "route_lookup": Query("show ip route {address}", ADDRESS),
    },
    "juniper_junos": {
        "version": Query("show version", NO_SLOTS),
        "uptime": Query("show system uptime", NO_SLOTS),
        "system_alarms": Query("show system alarms", NO_SLOTS),
        "chassis_alarms": Query("show chassis alarms", NO_SLOTS),
        "hardware": Query("show chassis hardware", NO_SLOTS),
        "interfaces": Query("show interfaces terse", NO_SLOTS),
        "route_summary": Query("show route summary", NO_SLOTS),
        "interface_details": Query("show interfaces {interface} extensive | no-more", INTERFACE),
        "route_lookup": Query("show route {address} detail | no-more", ADDRESS),
    },
}


SAFE_INTERFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,63}")
SAFE_SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}")


def normalize_platform(platform: str) -> str:
    normalized = PLATFORM_MAP.get(platform.strip().lower())
    if not normalized:
        raise ValueError(f"unsupported platform: {platform}")
    return normalized


def _validate_slot(value: str, kind: str) -> str:
    if kind == "interface" and SAFE_INTERFACE.fullmatch(value):
        return value
    if kind == "service" and SAFE_SERVICE.fullmatch(value):
        return value
    if kind == "address":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
    raise ValueError(f"invalid typed {kind} value")


def render_read_query(
    platform: str,
    query_name: str,
    parameters: Mapping[str, str] | None,
    inventory: Mapping[str, tuple[str, ...]],
) -> tuple[str, str]:
    normalized = normalize_platform(platform)
    try:
        query = READ_QUERIES[normalized][query_name]
    except KeyError as exc:
        raise ValueError(f"unknown read query for platform: {normalized}") from exc
    supplied = dict(parameters or {})
    if set(supplied) != set(query.slots):
        raise ValueError(f"query parameters must be exactly: {sorted(query.slots)}")
    rendered: dict[str, str] = {}
    for name, slot in query.slots.items():
        value = _validate_slot(str(supplied[name]), slot.kind)
        allowed = inventory.get(slot.inventory, ())
        if value not in allowed:
            raise ValueError(f"{name} is not enrolled in target inventory")
        rendered[name] = value
    fields = {name for _, name, _, _ in Formatter().parse(query.command) if name}
    if fields != set(query.slots):
        raise RuntimeError("query template and slot declaration differ")
    return normalized, query.command.format_map(rendered)


def public_query_catalog() -> dict[str, dict[str, list[str]]]:
    return {
        platform: {
            name: sorted(slot.inventory for slot in query.slots.values())
            for name, query in sorted(queries.items())
        }
        for platform, queries in sorted(READ_QUERIES.items())
    }
