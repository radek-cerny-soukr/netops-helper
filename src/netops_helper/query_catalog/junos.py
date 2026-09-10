"""Curated Junos OS 23.4R2 phase-1 diagnostic queries."""

from __future__ import annotations

from .model import IPV4_ADDRESS, IPV6_ADDRESS, NO_SLOTS, Query, Slot


def _interface_slot(kind: str) -> dict[str, Slot]:
    return {"interface": Slot("interfaces", kind)}


COMMON_QUERIES: dict[str, Query] = {
    "version": Query("show version | no-more", NO_SLOTS, "Show software and platform version details."),
    "uptime": Query("show system uptime | no-more", NO_SLOTS, "Show system uptime."),
    "system_alarms": Query("show system alarms | no-more", NO_SLOTS, "Show active system alarms."),
    "chassis_alarms": Query("show chassis alarms | no-more", NO_SLOTS, "Show active chassis alarms."),
    "hardware": Query("show chassis hardware | no-more", NO_SLOTS, "Show installed chassis hardware."),
    "environment": Query("show chassis environment | no-more", NO_SLOTS, "Show chassis environmental status."),
    "interfaces": Query("show interfaces terse | no-more", NO_SLOTS, "Summarize physical and logical interface state.", high_volume=True),
    "interface_details": Query("show interfaces {interface} extensive | no-more", _interface_slot("junos_interface"), "Show extensive operational details for one enrolled interface."),
    "interface_optics": Query("show interfaces diagnostics optics {interface} | no-more", _interface_slot("junos_physical_interface"), "Show optical diagnostics for one enrolled physical interface."),
    "route_summary": Query("show route summary | no-more", NO_SLOTS, "Summarize the routing tables."),
    "route_lookup": Query("show route {address} detail | no-more", IPV4_ADDRESS, "Look up one enrolled IPv4 route."),
    "ipv6_route_lookup": Query("show route {address} detail | no-more", IPV6_ADDRESS, "Look up one enrolled IPv6 route."),
    "arp_table": Query("show arp no-resolve | no-more", NO_SLOTS, "Show the IPv4 ARP table without name resolution.", high_volume=True),
    "arp_interface": Query("show arp no-resolve interface {interface} | no-more", _interface_slot("junos_logical_interface"), "Show ARP entries for one enrolled logical interface.", high_volume=True),
    "ipv6_neighbors": Query("show ipv6 neighbors | no-more", NO_SLOTS, "Show the IPv6 neighbor table.", high_volume=True),
    "ipv6_neighbors_interface": Query("show ipv6 neighbors interface {interface} | no-more", _interface_slot("junos_logical_interface"), "Show IPv6 neighbors for one enrolled logical interface.", high_volume=True),
    "lldp_neighbors": Query("show lldp neighbors | no-more", NO_SLOTS, "Summarize LLDP neighbors.", high_volume=True),
    "lldp_neighbors_interface": Query("show lldp neighbors interface {interface} | no-more", _interface_slot("junos_physical_interface"), "Show LLDP neighbors for one enrolled physical interface."),
    "lacp_interfaces": Query("show lacp interfaces | no-more", NO_SLOTS, "Show LACP state for supported interfaces.", high_volume=True),
    "lacp_interface": Query("show lacp interfaces {interface} | no-more", _interface_slot("junos_lacp_interface"), "Show LACP state for one enrolled interface."),
    "bgp_summary": Query("show bgp summary | no-more", NO_SLOTS, "Summarize BGP peer state.", high_volume=True),
    "ospf_neighbors": Query("show ospf neighbor | no-more", NO_SLOTS, "Show OSPFv2 neighbor state.", high_volume=True),
    "ospf_neighbors_interface": Query("show ospf neighbor interface {interface} | no-more", _interface_slot("junos_logical_interface"), "Show OSPFv2 neighbors for one enrolled logical interface."),
    "ospfv3_neighbors": Query("show ospf3 neighbor | no-more", NO_SLOTS, "Show OSPFv3 neighbor state.", high_volume=True),
    "ospfv3_neighbors_interface": Query("show ospf3 neighbor interface {interface} | no-more", _interface_slot("junos_logical_interface"), "Show OSPFv3 neighbors for one enrolled logical interface."),
}


ELS_QUERIES: dict[str, Query] = {
    **COMMON_QUERIES,
    "vlans": Query("show vlans brief | no-more", NO_SLOTS, "Show ELS VLAN state.", high_volume=True),
    "mac_table": Query("show ethernet-switching table | no-more", NO_SLOTS, "Show the ELS Ethernet switching table.", high_volume=True),
    "stp_bridge": Query("show spanning-tree bridge | no-more", NO_SLOTS, "Show ELS spanning-tree bridge state.", high_volume=True),
    "virtual_chassis": Query("show virtual-chassis status | no-more", NO_SLOTS, "Show virtual chassis status."),
}
