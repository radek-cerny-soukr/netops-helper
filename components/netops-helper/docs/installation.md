# Installation

NetOps Helper phase 1 uses three trust zones:

- a dedicated read-only MCP agent/session;
- a local proxy host holding aliases, credentials, host keys, and target policy;
- an execution host running the isolated container and reaching enrolled targets.

The proxy and execution host may share one machine in a deployment. Device-side authorization, the egress contract, and the dedicated client session remain separate mandatory boundaries.

## 1. Prepare target accounts

Create a dedicated identity on every target and enforce read-only permissions on that platform. Do not reuse administrator, Docker-enabled, sudo-capable, or future write-service credentials. Test both the intended named diagnostics and denial of configuration display/export, configuration mode, file writes, maintenance, privilege escalation, and shell escape over the same SSH/AAA path that NetOps Helper will use.

For FortiOS, an administrator must configure and verify persistent console `output standard` before enrollment. The runtime never changes paging mode. See [Read-only accounts](read-only-accounts.md).

If SNMP is required, create a separate read-only community that is not the SSH password. SNMPv2c sends it in plaintext, so restrict source and destination ACLs and the enrolled UDP egress scope.

The same target `login` and `password` are used for SSH, SFTP, FTPS, and plain FTP. Plain FTP sends those credentials without encryption. Prefer FTPS; if legacy FTP is unavoidable, use a separate remote FTP identity and target alias, and enforce rejection of SSH/SFTP for that identity on the target. Policy `sftp_roots` also authorizes `sftp_stat`, so policy alone is not an FTP-only protocol boundary. Review [credential vault structure and protocol use](configuration.md#credential-vault-structure-and-protocol-use) before creating accounts.

## 2. Prepare configuration and trust on the proxy host

Use `$XDG_CONFIG_HOME/netops-helper` or set the documented `NETOPS_*` variables.

1. Create one valid credential JSON object with mode `600`; it is not JSONL. Follow the [runner/target vault structure and synthetic example](configuration.md#credential-vault-structure-and-protocol-use).
2. Copy `config/target-policy.example.json` and replace every documentation address and scope.
3. Declare exact platform, query, inventory, metadata/listing-root, and egress policy and a suitable rate limit for each target alias.
4. Enroll the runner and every SSH/SFTP target in the configured `known_hosts` through an independently trusted host-key channel.
5. Keep the `NETOPS_MASTER_ALIAS` runner record separate from every device alias and omit it from target policy; the proxy rejects it as a target.
6. If `NETOPS_MASTER_ALIAS` is customized, export the identical value when launching the proxy and when generating every egress bundle.

The runtime target `host` is either a canonical IPv4 literal or a canonical lowercase hostname. A hostname target additionally needs explicit enrolled canonical IPv4 results, DNS permission, and configured resolvers. IPv6 target hosts are not supported in this release.

For private TLS or FTPS trust, complete [the private CA, SAN, and FTPS pin procedure](configuration.md#private-tls-and-ftps-ca-san-and-pins) before building the runner image. The stock image works with certificates chaining to its public system trust. It does not normally trust a private device CA or self-signed device certificate.

## 3. Build and create stopped Docker resources

Install Docker Engine with Compose v2 and obtain a verified release on the execution host. The Compose network contract is:

- network name `netops-helper`;
- bridge interface `nh-egress0`;
- `internal: false` so targets remain reachable;
- `enable_ipv6: false` as the network-scoped IPv6 boundary.

Do not change `internal` to true as an egress-hardening shortcut; it removes required external connectivity. Do not force a fixed bridge subnet unless it was independently designed for that host. Interface-based matching does not need a fixed subnet, and a fixed allocation can collide with existing networks.

Build the digest-pinned image, then create the network and container without starting the service:

```bash
docker compose build --pull=false
docker compose up --no-start --no-build
docker compose ps --all
docker network inspect netops-helper
```

The official Docker Compose CLI defines `up --no-start` as creating services without starting them. The explicit network declaration causes Compose to create the named network as part of that operation. See the official [`docker compose up` reference](https://docs.docker.com/reference/cli/docker/compose/up/) and [Compose network reference](https://docs.docker.com/reference/compose-file/networks/).

Verify that the container is not running and that the inspected network is the bridge `nh-egress0` with `EnableIPv6: false`. Stop here if any value differs. Do not use `docker compose up -d` at this stage: that would start the helper before egress enforcement is verified.

The runner SSH identity later used by the proxy needs narrowly constrained permission to invoke the fixed remote command `docker exec -i netops-helper python -m netops_helper.server`. The stock proxy invokes OpenSSH with `ssh -T`, so it allocates no terminal, and explicitly disables agent, X11, TCP, tunnel, proxy-command, jump-host, local-command, environment, and multiplexing paths. Docker group membership is effectively privileged host access; use a dedicated runner account constrained to that command or another independently reviewed restriction.

The stock proxy supports only password and keyboard-interactive runner authentication, limits prompting to one attempt, and explicitly sets `PubkeyAuthentication=no`. The runner vault record therefore contains the password used for that SSH hop. Key- or certificate-based authentication may be preferable in a separately designed transport adapter, but the stock proxy does not implement it and this documentation does not claim otherwise.

## 4. Generate the egress bundle on the proxy host

Run the generator from the same verified source revision that is deployed on the runner. It reads the mode-`600` vault and target policy, validates their relationship, and atomically writes a mode-`600` bundle. The bundle contains no credentials, logins, aliases, hostnames, TLS names, or host-key material, but it does reveal destination addresses, ports, LAN scopes, and resolver scope.

```bash
python3 scripts/generate_egress_rules.py \
  --vault /path/to/vault.json \
  --policy /path/to/target-policy.json \
  --output /restricted/path/netops-helper-egress.json
```

Generation must finish with exit status zero. Do not pass JSON or credentials inline, and do not place the output in the public repository.

If the runner alias is not the default, pass the same value used by the proxy:

```bash
NETOPS_MASTER_ALIAS=transport-runner python3 scripts/generate_egress_rules.py \
  --vault /path/to/vault.json \
  --policy /path/to/target-policy.json \
  --output /restricted/path/netops-helper-egress.json
```

If the proxy and runner are different hosts:

1. compute the bundle's SHA-256 digest locally;
2. transfer it over an approved encrypted channel whose runner identity is verified independently;
3. store it in a runner-local restricted directory with mode `600`;
4. recompute and compare the digest on the runner through a separate trusted observation.

A successful transfer proves only byte equality. It does not replace review of the bundle's intended network scope. `manifest_sha256` later verifies only the normalized manifest inside that bundle; it is not a digest of the vault, policy, source revision, aliases, or original input bytes.

## 5. Review, explicitly apply, and check egress

Read [Egress control](egress-control.md) before changing the host firewall. Retain an out-of-band recovery path.

Review the schema-3 bundle on the runner before applying it. Confirm at minimum:

- `manifest_sha256` matches a fresh digest of the canonical normalized manifest, the ruleset was rendered from that manifest, and the effective network scope is intended;
- profile is the intended `strict-target` or explicitly accepted `lan-constrained` profile; for `lan-constrained`, every CIDR is a canonical subnet wholly inside RFC1918 space and every target destination lies within the declared LAN union;
- network and bridge are exactly `netops-helper` and `nh-egress0`;
- `network_ipv6_enabled` is `false` and `ipv6_boundary` is `docker-network-disabled`;
- every IPv4 destination, TCP/UDP port or range, resolver, and LAN CIDR is expected; remember that `lan-constrained` applies the union of all enrolled ports/ranges and ICMP permission to every declared LAN CIDR;
- the final IPv4 managed-chain action is drop;
- the bundle exposes no unintended environment data.

Then invoke the privileged apply helper with the explicit consent flag and immediately run the read-only checker:

```bash
sudo python3 scripts/apply_egress_rules.py \
  --bundle /restricted/path/netops-helper-egress.json --apply
sudo python3 scripts/check_egress_rules.py \
  --expected /restricted/path/netops-helper-egress.json
```

Continue only after `egress_apply=ok` and `egress_check=ok`. The helper requires root, a mode-`600` bundle, Docker inspection, `nft`, and `iptables-save`/`iptables-restore`. It rejects native Docker nftables, an indeterminate backend, an unreachable IPv4 DOCKER-USER path, a network mismatch, or any Docker IPv6 state other than exact boolean false.

Bundle schema 3 contains one IPv4 ruleset and apply uses one IPv4 `iptables-restore` COMMIT. It never invokes ip6tables and does not claim an IPv6 firewall transaction. IPv6 is instead disabled on this Docker network by Compose. DOCKER-USER filters forwarded bridge traffic; it does not protect services reached through the runner's INPUT path. The checker validates its defined network and forwarding contract, not complete host containment.

## 6. Start the service only after the check

Start the already-created stopped container and confirm its state:

```bash
docker compose start
docker compose ps
```

If start causes an unexpected recreate or network change, stop the service, rerun the checker, and investigate before reconnecting a client. Do not replace this guarded first start with `docker compose up -d`.

## 7. Connect an MCP client

Configure any compatible client to launch `python3` with the absolute path to `scripts/remote_mcp_proxy.py` as a stdio MCP server. Keep client-specific settings outside the repository.

Use a dedicated read-only agent/session with no generic shell, write-capable filesystem, deployment, configuration, or mutating tools. Restart the client after changing its MCP configuration.

## 8. Validate the deployment

Run portable source checks in a suitable development environment, from this component's directory (`components/netops-helper/` in the `netops` repository):

```bash
PYTHONPATH=src python tests/run_tests.py
PYTHONPATH=src python tests/test_engine_contracts.py
python tests/test_proxy_contracts.py
python tests/test_egress_scripts.py
python tests/test_apply_egress_rules.py
python scripts/check_public_release.py
```

On the maintained ARM64 release builder, install the locked runtime and run the complete suite with mandatory runtime tests:

```bash
NETOPS_REQUIRE_RUNTIME_TESTS=1 python -m pytest -q
```

Then start a fresh dedicated client session:

1. Call `helper_status`; confirm `write_tools` is empty and review `invalid_target_count` and per-target rate state.
2. Choose only an alias returned in `target_aliases`.
3. Call `target_scope`; review query, inventory, metadata/listing root, egress, host-key, SNMP, and rate state. Remember that egress addresses and other returned scope are topology-sensitive.
4. Compare enabled names and typed slots with `read_query_catalog`.
5. Execute one harmless enrolled query against a controlled test target.
6. Confirm target-side authentication/authorization logging and the expected two-phase audit pair.
7. Confirm a forbidden query or malformed parameter is rejected without a target connection.

The ARM64 live network test must also verify:

- allowed and denied target address/port combinations;
- IPv6 remains unavailable to containers on this network;
- expected DNS behavior through Docker embedded DNS at `127.0.0.11`;
- attempts to reach runner-local listening services through bridge and host addresses;
- survival and ordering of the DOCKER-USER jump across Docker restart;
- checker detection of rule drift.

DOCKER-USER alone does not cover INPUT. If runner-host services require protection, design a host-specific INPUT policy only after observing actual Docker DNS/NAT behavior, then retest it.

## Change procedure

Any change to vault targets or connection ports, policy, metadata/listing roots, resolver scope, Compose network, or Docker networking requires the guarded sequence again:

1. stop the service;
2. regenerate and securely transfer a fresh bundle;
3. review it and retain recovery access;
4. explicitly apply it;
5. run the checker and live negative tests;
6. start the service only after all checks pass.

Do not assume that a previously installed rule follows enrollment changes automatically. Run the checker after Docker restart or network recreation even when the policy did not change.

## Removal

Disconnect the MCP client and stop the container. Remove or replace the tool-owned host-firewall chain through a reviewed operator procedure before removing the Compose network. Preserve or securely dispose of the audit volume according to retention policy. Removing the MCP connection does not remove the credential file, host keys, policy, transferred bundle, or host firewall state.
