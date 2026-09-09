# NetOps Helper

NetOps Helper phase 1 is a security-focused, read-only MCP server for bounded network troubleshooting. It is designed to give an AI agent useful diagnostic visibility without giving that agent a configuration path.

Operators address explicitly enrolled devices by alias. A local stdio proxy injects one target's credentials only after the MCP client boundary, transports the request over verified SSH, and invokes an isolated container on a runner. Device output keeps the addresses and identifiers required for correlation while explicit secrets are removed.

This is a home-lab project for experienced operators and security reviewers. It is not an enterprise orchestrator, a replacement for device-side authorization, or proof that a diagnostic conclusion is correct.

## Architecture

```text
dedicated read-only agent/session
  -> local stdio proxy: target scope, credential injection, secret redaction
  -> verified SSH transport
  -> docker exec -i netops-helper
  -> isolated phase-1 read-only MCP server
  -> device account with externally enforced read-only permissions
```

The required order of controls is:

1. read-only accounts enforced by each target platform;
2. named query templates and exact HTTPS endpoints bound to per-target policy;
3. best-effort secret response redaction;
4. explicit byte pagination instead of silent truncation;
5. per-target request limiting and bounded SSH pagination caching;
6. a standalone phase-1 server with no write tools.

## Capabilities

- DNS, TCP, ICMP, traceroute, TLS, and exact-endpoint-allowlisted verified HTTPS diagnostics.
- Named SSH troubleshooting queries for FortiOS, Cisco IOS/IOS XE, Arista EOS, ExtremeXOS, Junos, and Linux.
- Typed parameters selected from per-target interface, service, and address inventories.
- SNMPv2c GET with the community value held only for the request.
- SFTP metadata and paginated UTF-8 reads under per-target non-root paths.
- FTPS directory listing and explicitly acknowledged read-only plain FTP listing.
- Explicit pagination metadata and a stable content digest for long output.

See [Tool reference](docs/tools.md), [Read-only accounts](docs/read-only-accounts.md), [Configuration](docs/configuration.md), and [Installation](docs/installation.md).

## Deliberate non-capabilities

Phase 1 provides no configuration, prepare/apply workflow, upload, deletion, restart, reboot, process control, software installation, device discovery, arbitrary shell, raw CLI command input, or autonomous target expansion. A future write service must be a separate binary, container, credential set, and client profile.

## Security properties

- The helper exposes no listening port; MCP uses SSH-tunneled stdio.
- The container runs non-root with a read-only root filesystem, no Linux capabilities, `no-new-privileges`, resource limits, and no Docker socket.
- Every target must declare `account_role: "read-only"`; the operator must separately verify the actual device-side role.
- FortiOS sessions use a no-paging-write driver, require preverified `output standard`, and reject SHA-1 KEX-only targets.
- SSH and SFTP require pre-enrolled host keys.
- The agent supplies query names and typed parameters, never raw commands.
- Inventory-bound slots prevent device output from becoming a new command argument or expanding target scope.
- IP, IPv6, MAC, hostname, username, email, and serial values remain visible because troubleshooting requires correlation.
- Injected credentials and recognized secret forms are redacted on a best-effort basis; read policy and remote permissions must keep secret-bearing data out of scope.
- Every device response is marked as untrusted data and must run in a dedicated read-only agent/session.
- Audit JSONL contains allowlisted metadata only and rotates into five 2 MB segments.

Read [Security model](docs/security-model.md), [Security policy](SECURITY.md), and the release-specific [known vulnerability findings](docs/known-vulnerabilities.md) before deployment.

## Requirements

- A Linux ARM64 runner with Docker Engine and Compose v2.
- A local MCP client host with Python 3.12+, OpenSSH, and verified host keys.
- Dedicated device identities whose read-only permissions are enforced on the targets.
- A local credential source and target policy that are never shipped with the source or container image.
- A dedicated agent/session without shell, write-capable file, deployment, or mutating MCP tools.

## Quick start

1. Clone a verified release.
2. Create dedicated read-only target accounts and independently test their effective permissions.
3. Copy `config/target-policy.example.json` to the configured per-user location. Set `account_role`, exact HTTPS endpoints, the smallest required inventories and file-read roots, and a conservative request limit. Complete the additional FortiOS output-mode prerequisite when applicable.
4. Create the local credential file with mode `600`. Never commit it or place real values on a command line.
5. Pre-enroll the runner and target SSH host keys.
6. Build and start the isolated helper:

   ```bash
   docker compose build --pull=false
   docker compose up -d --no-build
   ```

7. Configure `scripts/remote_mcp_proxy.py` as a stdio MCP server in a dedicated read-only profile of any compatible client. Start a fresh session, call `helper_status`, and test a harmless query against a lab target.

The default password-backed credential file is a portability compromise, not the preferred production secret design. An external broker and platform-appropriate key or certificate authentication are recommended for a future hardened deployment. The standard Compose network permits egress required for diagnostics; enforce destination and port restrictions on the execution host or an externally managed container network.

## Development

Use Python 3.12, install the locked dependencies and pytest, then run:

```bash
python -m pytest -q
PYTHONPATH=src python tests/run_tests.py
python scripts/check_public_release.py
```

The base image is digest-pinned. Runtime dependencies are hash-locked, and release metadata includes CycloneDX SBOM data. A clean test run is necessary but not sufficient; review the source diff, effective target permissions, vulnerability scan, license inventory, and residual risks.

## License

MIT. See [LICENSE](LICENSE).
