# Installation

NetOps Helper phase 1 uses three trust zones:

- a dedicated read-only MCP agent/session;
- a local proxy host holding target aliases, credentials, host keys, and target policy;
- an execution host running the isolated container and reaching enrolled targets.

The proxy and execution host may be the same machine in a lab. The read-only agent profile and device-side authorization remain mandatory boundaries.

## 1. Prepare target accounts

Create a dedicated identity on every target and enforce read-only permissions on that platform. Do not reuse administrator, Docker-enabled, sudo-capable, or future write-service credentials. Independently test effective denial of configuration and maintenance operations. For FortiOS, also configure and verify console `output standard` before enrollment. See [Read-only accounts](read-only-accounts.md).

## 2. Prepare the execution host

Install Docker Engine with Compose v2 and clone a verified release. Before starting the container, apply host firewall or externally managed container-network rules which restrict egress to the enrolled target addresses, DNS resolvers, and required ports. The supplied bridge must permit outbound diagnostics and cannot express per-target destination ACLs by itself.

Build the digest-pinned image:

```bash
docker compose build --pull=false
docker compose up -d --no-build
docker compose ps
```

The runner SSH identity needs narrowly constrained permission to invoke the fixed NetOps Helper container command. Docker group membership is effectively privileged access to the execution host; prefer a dedicated account with forced-command or equivalent restrictions.

## 3. Prepare local configuration

Use `$XDG_CONFIG_HOME/netops-helper` or set the documented `NETOPS_*` variables. Create the credential JSON with mode `600`, copy `config/target-policy.example.json`, declare `account_role: "read-only"`, and enroll only required interface, service, address, exact HTTPS-endpoint, and file-read scopes. Set a per-target rate limit appropriate for lockout and load thresholds. Never make the runner's `NETOPS_MASTER_ALIAS` a target; the proxy rejects it explicitly.

Enroll the execution host and every SSH/SFTP target in the configured `known_hosts`. Unknown or changed keys must fail closed.

## 4. Connect an MCP client

Configure the client to launch `python3` with the absolute path to `scripts/remote_mcp_proxy.py` as a stdio MCP server. MCP client configuration formats differ, so keep client-specific settings outside this repository. The proxy reads its paths from the documented `NETOPS_*` environment variables.

Use a dedicated read-only agent or client profile with no generic shell, write-capable filesystem, deployment, configuration, or mutating MCP tools. Device output is untrusted and must not share a session with broader capabilities. Restart the client after changing its MCP configuration.

## 5. Validate

Run locally:

```bash
python -m pytest -q
PYTHONPATH=src python tests/run_tests.py
python scripts/check_public_release.py
```

Start a fresh dedicated session, call `helper_status`, verify that `write_tools` is empty, inspect `read_query_catalog`, and execute one harmless query against a lab target. Stop if the target account's effective read-only permissions have not been independently verified.

## Removal

Disconnect the MCP server and stop/remove its container. Preserve or securely dispose of the audit volume according to retention policy. Removing the MCP connection does not remove the local credential file, host keys, or target policy.
