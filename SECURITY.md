# Security policy

## Supported versions

Security fixes are maintained for the latest tagged minor release. Pre-1.0 releases may make breaking configuration changes when required to fail closed.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose credentials, device access, private network data, or a capability-boundary bypass. Contact the repository owner privately through GitHub Security Advisories. Never include live credentials, addresses, configurations, or command output.

## Threats in scope

- Leakage of credentials or private keys.
- Authentication-context, target-alias, or inventory-scope confusion.
- SSH host-key bypass.
- Escape from typed query templates, target inventories, or SFTP read roots.
- A write-capable tool appearing in the phase-1 MCP server or client profile.
- Prompt injection through device-controlled output.
- Missing device-operation audit coverage, persistent secret-bearing audit data, or unbounded audit growth.
- Container privilege or filesystem-hardening regressions.
- Supply-chain substitution of base images or Python dependencies.

## Required deployment boundary

Every target account must be restricted to read-only permissions by the target platform. Local templates and `account_role` enrollment are defense in depth, not substitutes for remote authorization.

Use a dedicated agent/session with no mutating MCP tools, generic shell, write-capable file tools, or deployment integrations. Client-side safety instructions help the model handle untrusted device text, but prompt instructions are not a security boundary.

## Residual risk

Device output remains sensitive and attacker-controlled even after best-effort secret redaction. Plain FTP is unencrypted, and SNMPv2c lacks modern confidentiality. The supported password-backed credential file and `SSH_ASKPASS` environment are compatibility compromises. Client-side path roots do not replace remote permissions or chroot. The standard container network permits diagnostic egress; host-level destination filtering is required if compromise must not expose the wider LAN or Internet. A compromised client, runner, dependency, or target can still return malicious data. No release is certified for a regulatory framework.
