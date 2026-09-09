# Changelog

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
