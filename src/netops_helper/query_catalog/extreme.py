"""Curated Extreme Networks Switch Engine phase-1 diagnostic queries."""

from __future__ import annotations

from .model import IPV4_ADDRESS, IPV6_ADDRESS, NO_SLOTS, Query, Slot


PHYSICAL_PORT = {
    "interface": Slot("interfaces", "extreme_physical_port"),
}


QUERIES: dict[str, Query] = {
    "switch": Query("show switch", NO_SLOTS, "Show switch identity, role, and operating status."),
    "version": Query(
        "show version", NO_SLOTS, "Show hardware and software version information.",
    ),
    "memory": Query("show memory", NO_SLOTS, "Show system memory utilization."),
    "cpu_monitoring": Query(
        "show cpu-monitoring",
        NO_SLOTS,
        "Show CPU utilization history.",
        high_volume=True,
    ),
    "processes": Query(
        "show process",
        NO_SLOTS,
        "Show operating status for system processes.",
        high_volume=True,
    ),
    "diagnostics": Query(
        "show diagnostics",
        NO_SLOTS,
        "Show results from the most recent diagnostic test.",
    ),
    "temperature": Query(
        "show temperature", NO_SLOTS, "Show system temperature and component status.",
    ),
    "fans": Query("show fans", NO_SLOTS, "Show fan health."),
    "power": Query("show power", NO_SLOTS, "Show power-supply health."),
    "ports": Query(
        "show ports no-refresh",
        NO_SLOTS,
        "Show a one-shot summary of all ports.",
        high_volume=True,
    ),
    "ports_configuration": Query(
        "show ports configuration no-refresh",
        NO_SLOTS,
        "Show a one-shot Layer 1 port snapshot with administrative, link, "
        "autonegotiation, speed, duplex, and media state.",
        high_volume=True,
    ),
    "interface_details": Query(
        "show port {interface} information detail",
        PHYSICAL_PORT,
        "Show detailed state for one enrolled port.",
    ),
    "interface_statistics": Query(
        "show ports {interface} statistics no-refresh",
        PHYSICAL_PORT,
        "Show a one-shot statistics snapshot for one enrolled port.",
    ),
    "interface_rx_errors": Query(
        "show ports {interface} rxerrors no-refresh",
        PHYSICAL_PORT,
        "Show a one-shot receive-error snapshot for one enrolled port.",
    ),
    "interface_tx_errors": Query(
        "show ports {interface} txerrors no-refresh",
        PHYSICAL_PORT,
        "Show a one-shot transmit-error snapshot for one enrolled port.",
    ),
    "interface_transceiver": Query(
        "show ports {interface} transceiver information detail",
        PHYSICAL_PORT,
        "Show optical transceiver diagnostics for one enrolled port.",
    ),
    "route_summary": Query(
        "show iproute summary", NO_SLOTS, "Summarize the IPv4 routing table.",
    ),
    "ipv6_route_summary": Query(
        "show iproute ipv6 summary", NO_SLOTS, "Summarize the IPv6 routing table.",
    ),
    "arp_table": Query(
        "show iparp", NO_SLOTS, "Show the IPv4 ARP table.", high_volume=True,
    ),
    "arp_address": Query(
        "show iparp {address}",
        IPV4_ADDRESS,
        "Show the ARP entry for one enrolled IPv4 address.",
    ),
    "arp_interface": Query(
        "show iparp port {interface}",
        PHYSICAL_PORT,
        "Show ARP entries learned on one enrolled port.",
        high_volume=True,
    ),
    "ipv6_neighbors": Query(
        "show neighbor-discovery cache ipv6",
        NO_SLOTS,
        "Show the IPv6 neighbor cache.",
        high_volume=True,
    ),
    "ipv6_neighbor_address": Query(
        "show neighbor-discovery cache ipv6 {address}",
        IPV6_ADDRESS,
        "Show the neighbor entry for one enrolled IPv6 address.",
    ),
    "mac_table": Query(
        "show fdb", NO_SLOTS, "Show the forwarding database.", high_volume=True,
    ),
    "mac_interface": Query(
        "show fdb ports {interface}",
        PHYSICAL_PORT,
        "Show forwarding entries learned on one enrolled port.",
        high_volume=True,
    ),
    "lldp_neighbors": Query(
        "show lldp neighbors",
        NO_SLOTS,
        "Summarize LLDP neighbors on all ports.",
        high_volume=True,
    ),
    "lldp_interface": Query(
        "show lldp port {interface} neighbors",
        PHYSICAL_PORT,
        "Summarize LLDP neighbors on one enrolled port.",
    ),
    "lldp_interface_details": Query(
        "show lldp port {interface} neighbors detailed",
        PHYSICAL_PORT,
        "Show detailed LLDP neighbors on one enrolled port.",
    ),
    "vlan_summary": Query(
        "show vlan", NO_SLOTS, "Summarize all VLANs.", high_volume=True,
    ),
    "sharing": Query("show sharing", NO_SLOTS, "Show link aggregation groups.", high_volume=True),
    "lacp": Query("show lacp", NO_SLOTS, "Show LACP operating state.", high_volume=True),
    "stp_summary": Query(
        "show stpd", NO_SLOTS, "Summarize spanning-tree domains.",
        high_volume=True,
    ),
}
