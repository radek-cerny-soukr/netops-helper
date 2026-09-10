# Changelog

## 0.2.0 - 2026-09-10

Second public release. This release keeps phase 1 deliberately read-only while making the enrolled diagnostic scope discoverable and substantially expanding bounded troubleshooting coverage.

### Breaking capability boundary

- Remove the generic `https_get` and `sftp_read_text` body-read tools from Phase 1. Retain certificate-only `tls_probe`, metadata-only `sftp_stat`, and directory-name-only `ftp_list`.
- Remove the `route_trace` traceroute tool that 0.1.0 registered. Bounded reachability now relies on `icmp_probe`, `tcp_probe`, and enrolled routing, neighbor, and forwarding queries; the release gate rejects any tool reintroducing it.
- Reject the legacy `https_endpoints` target-policy key as an unknown field instead of silently ignoring it. Deployments upgrading from 0.1.0 must remove that key before enrollment succeeds.
- Reserve HTTP response bodies, remote file contents, and any future configuration read for a separately designed Phase 2 threat model and execution boundary.

### Operability

- Add alias discovery to `helper_status` and a credential-free but topology-sensitive `target_scope` view of each enrolled inventory, metadata/listing root, and egress destination.
- Distinguish proxy policy, credential, vault-permission, rate-limit, transport, and remote-process failures, and derive fixed categorized transport diagnostics from sanitized SSH stderr without relaying the raw stream.
- Raise the default per-target request budget for normal troubleshooting and keep SSH continuation pages within one bounded snapshot instead of reconnecting or rerunning the command.
- Add stable SSH snapshot digests, explicit pagination metadata, a bounded cache lifetime, and fail-closed handling when complete SSH output exceeds the two-megabyte safety ceiling.

### Query policy

- Replace the small shared network catalogue with one authoritative modular registry for Linux, FortiOS, Extreme Switch Engine, Cisco IOS, IOS-XE and NX-OS, Arista EOS, and Junos with and without ELS.
- Add reviewed operational queries for interfaces, routes, neighbors, forwarding tables, discovery protocols, link aggregation, spanning tree, environmental state, HA and routing protocols where supported.
- Bind every parameterized query to typed per-target inventories with vendor-specific interface grammars and canonical IPv4/IPv6 validation.
- Publish deterministic query metadata, descriptions, typed slots, and high-volume scheduling hints from the same registry used by authorization and rendering. Vendor source references are published in the generated catalogue documentation, not in the runtime metadata.
- Continue to forbid running, startup, full, backup, and exported configuration; arbitrary CLI, general log browsing, debug, capture, support bundles, shell, remote file-content access, and write or maintenance actions remain outside phase 1. Traceroute leaves phase 1 with `route_trace`.

### Security

- Give SNMPv2c a dedicated optional `snmp_community`; never fall back to the SSH password and reject enrollment that reuses the same secret.
- Inject only host-key records matching the selected target and harden the proxy SSH invocation against user configuration, forwarding, multiplexing, proxying, environment forwarding, and interactive terminal allocation.
- Remove the temporary askpass executable; credentials now remain in a bounded child environment and are removed before remote container execution.
- Write a durable audit `started` record before every device operation and a linked terminal record afterward; an unavailable mandatory audit sink fails closed with an explicit audit error.
- Refine best-effort redaction so ordinary log prose remains readable while explicit password, community, token, private-key, and FortiOS encrypted-payload forms are removed.
- Keep the FortiOS no-paging-write driver and add a mock SSH wire test that verifies only the enrolled diagnostic command reaches the channel.

### Egress and deployment

- Give the Docker bridge a stable host interface name, disable IPv6 on that network, and add secret-free schema-validated generation, transactional application, rollback, and live checking of IPv4 DOCKER-USER egress rules.
- Derive egress destinations from the enrolled vault and policy, support a documented RFC1918-only intermediate profile, and require applying and checking host rules before the helper container starts.
- Document the residual runner INPUT path, the intentionally external bridge, private/self-signed CA image workflow, complete vulnerability-report burden, and upstream Netmiko session-preparation risk.
- Document the separate runner and target vault records, shared target credentials across SSH/SFTP/FTP transports, exact global egress schema, stock runner authentication contract, and FTPS pin semantics.

### Release assurance

- Expand dependency-free policy parity, proxy, query-catalogue, vendor-reference, sanitizer, egress, audit, pagination, and supply-chain contracts.
- Generate the public query catalogue deterministically and fail the release when registry, documentation, proxy, authorization, generator, or engine policy diverges.
- Make the public source export an integrity-manifested allowlist and recursively reject phase-1 configuration export or write implementations.
- Require the full runtime suite, including the FortiOS wire test, in hosted CI and the isolated ARM64 release gate.

## 0.1.0 - 2026-09-09

First public release.

### Security model

- Bind HTTPS GET to exact per-target path, port, and Basic-auth policy entries.
- Use a FortiOS read-only session driver which skips Netmiko paging writes and disables SHA-1 KEX.
- Audit every device-touching tool with secret-free operation metadata.
- Use a generic system-trust healthcheck and reject hard-coded environment trust files in release checks.
- Reject the runner master alias as a target and confine FTP/FTPS paths to configured read roots.
- Harden JSON-RPC proxy shape, error, batch, duplicate-ID, and bidirectional ID handling.
- Expand best-effort secret patterns, add per-target request limiting, and cache SSH continuation pages.
- Document the standard bridge's unrestricted egress as a residual risk requiring host/network ACLs.

- Ship phase 1 as a standalone read-only MCP server with no write, prepare/apply, upload, restart, or configuration tools.
- Require externally enforced read-only target accounts and explicit per-target enrollment.
- Replace raw and exact-string command input with named query templates and typed, inventory-bound slots.
- Preserve diagnostic IP, IPv6, MAC, hostname, username, email, and serial values while redacting explicit credentials, tokens, private keys, and FortiOS `ENC` payloads.
- Add explicit byte pagination and whole-content digests instead of silent 4 kB truncation.
- Mark device responses as untrusted data and require a dedicated read-only agent/session without broader tools.
- Keep the distribution agent-vendor neutral and expose the server through standard MCP stdio.
- Use verified SSH host keys, an isolated non-root/read-only container, secret-free bounded audit logs, hash-locked dependencies, a digest-pinned base image, SBOM generation, and release checks.

### Scope

- Provide bounded DNS, TCP, ICMP, traceroute, TLS, HTTPS, SSH, SNMP, SFTP-read, and FTPS/FTP-list diagnostics.
- Document deliberate non-capabilities, read-only account requirements, target inventory policy, prompt-injection handling, release procedures, and residual risks.
