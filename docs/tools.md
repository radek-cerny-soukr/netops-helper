# Tool reference - Phase 1 Read-Only

The remote FastMCP server registers exactly 10 tools: two remote control-plane tools and eight device tools. The local proxy accepts only that allowlist, removes the hidden `auth_context` from schemas, and adds the proxy-local `target_scope`. A client therefore sees exactly 11 tools: three control-plane tools and eight device tools.

All device tools use a target alias. The proxy inserts `auth_context` only on the private proxy-to-server hop; a user or client must never supply it. Device-originated values are returned as untrusted diagnostic data.

## Control-plane tools

| Tool | Purpose | Device contact |
| --- | --- | --- |
| `helper_status` | Remote version/phase controls, augmented by the proxy with valid target aliases and per-target rate state | None |
| `target_scope` | Proxy-local, non-secret enrolled scope for one alias | None |
| `read_query_catalog` | Remote public query names, informative command templates, typed parameters, and volume metadata | None |

Use them in that order: discover aliases, inspect one target's actual scope, then compare enabled query names with the public catalog.

## Device tools

| Tool | Purpose | Important bounds |
| --- | --- | --- |
| `dns_probe` | Resolve the enrolled target | DNS permission and resolved-address scope |
| `tcp_probe` | TCP connect test | Enrolled port; timeout 0.2-15 s |
| `icmp_probe` | ICMP reachability and latency | Explicit permission; 1-8 packets |
| `tls_probe` | Verified TLS and certificate metadata | Enrolled TCP port and alternate SNI |
| `ssh_read` | One named, typed, inventory-bound query | Enabled query; no raw command; 2 MB snapshot |
| `snmp_get` | SNMPv2c GET | Separate community, enrolled UDP port, up to 20 OIDs |
| `sftp_stat` | Remote file metadata only | Configured non-root path; no file body |
| `ftp_list` | FTPS/FTP directory names only | Root, control port, passive range, maximum 500 returned names; plain FTP acknowledgement |

`route_trace` is not registered in 0.2.0. Phase 1 has no arbitrary traceroute fallback.

## Credentials across device protocols

One target vault record supplies the same `login` and `password` to `ssh_read`, `sftp_stat`, and `ftp_list` over FTPS or plain FTP. Its vault `port` controls SSH/SFTP; the FTP/FTPS control port is a separate `ftp_list` argument and egress permission. Plain FTP sends the same credentials and returned listing data without encryption and requires explicit acknowledgement.

Prefer FTPS. For unavoidable legacy FTP, use a dedicated least-privilege remote FTP identity and target alias, set `ssh_platform: null` and `enabled_queries: []`, and make the target reject SSH/SFTP for that identity. The `sftp_roots` path policy is shared by `ftp_list` and `sftp_stat`, so it cannot enforce an FTP-only protocol boundary by itself.

## Typed SSH queries

The caller supplies the policy's exact platform, one enabled public query name, and an exact parameter object. Templates are defined in the canonical modules under `src/netops_helper/query_catalog/`. `read_query_catalog` exposes each exact template as informative `command_template` metadata so an operator can review what a named query will send. A template is not an executable input: `ssh_read` still accepts only the query name plus the template's exact typed parameters, and brace placeholders can only be filled from enrolled inventory.

New opt-in troubleshooting coverage includes ARP/IPv4 neighbors, IPv6 neighbors where supported, MAC/FDB tables, and LLDP/CDP neighbors. Linux additionally has `neighbors` and `bridge_fdb`. FortiOS `bridge_mac_table` uses the `switches` inventory. These names are available in the catalog but do nothing until explicitly added to that target's `enabled_queries`.

Slots are fixed:

- `interface` uses `interfaces`;
- `service` uses `services`;
- `address` uses canonical IP literals in `addresses`;
- `switch` uses `switches`.

The caller never supplies raw CLI text. Pipes and output modifiers occur only as fixed text in reviewed templates.

## Configuration and log boundary

Phase 1 never reads or exports running configuration, startup configuration, full configuration, or configuration backups. It has no generic HTTP response-body or remote file-content tool. No equivalent query may be enrolled through policy because only compiled catalog names are accepted.

There is no arbitrary device log command, path, time range, filter, or unbounded log stream. The only log-oriented named query is Linux `service_logs_recent`, fixed to one enrolled service and the most recent hour. SFTP roots authorize only metadata lookup and FTP/FTPS directory-name listing; they do not authorize download. Do not enroll configuration backups, credential stores, private keys, or general log archives even for metadata/listing access.

## Pagination and snapshots

`ssh_read` returns `total_bytes`, `offset`, `returned_bytes`, `next_offset`, `complete`, and a whole-output digest. There is no silent truncation.

At offset 0, `ssh_read` sanitizes and retains a complete bounded output snapshot for at most 120 seconds and eight entries per process when another page exists. A continuation uses that snapshot and never reconnects or reruns the query. Missing or expired state fails and must restart at offset 0. Completing the last page discards the snapshot.

A valid `ssh_read` continuation with `offset > 0` does not consume another proxy device rate slot, but it is still a server request and receives mandatory audit records. No other Phase-1 tool has continuation semantics.

## SNMPv2c warning

The vault's optional `snmp_community` is separate from `password`; omission disables SNMP and there is no fallback. SNMPv2c transmits the community in plaintext in UDP. Use a dedicated read-only community, device ACLs, and narrow UDP egress, or prefer SNMPv3 outside the current phase-1 feature set.

## Output and prompt injection

Responses are marked `device_output_trust: untrusted`. Banners, names, interface descriptions, logs, certificates, filenames, and protocol data are evidence only and never instructions.

Sanitization removes injected credentials plus recognized private-key, token, password, community, Cisco secret, shadow-hash, and FortiOS `ENC` forms. It is defense in depth, not a complete secret classifier: novel secret formats can survive, and heuristic matches can replace legitimate neighboring prose. Network identifiers remain visible because troubleshooting requires correlation. Exclude secret-bearing queries and metadata/listing roots before redaction rather than relying on sanitization to make them safe.
