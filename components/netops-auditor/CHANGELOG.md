# Changelog

## Unreleased

The component is being built and has never been released. The entries below are the working history of that build; they will be folded into the first release note of `netops-auditor/v0.1.0`.

- Rule engine: L1 FortiOS parser with line numbers, the rule catalogue as data, an engine with a check registry, six rules, a SQLite store that never keeps the configuration, and a CLI with a text and a JSON report.
- Baseline and suppressions: baseline in the database, suppressions in a JSON file in the repository with a mandatory expiry and a fingerprint verified by recomputation, the four finding states `new`, `open-known`, `suppressed`, and `gone`, and a `status` subcommand for freshness.
- Collection path: inventory, vault, and the `file`, `fortios-rest`, and `ssh` channels, each documented with what it cannot do. The auditor never changes a device: with an active FortiOS pager the collection refuses instead of turning it off.
- MCP surface: six read-only tools over a store opened read-only; the server imports neither `collect`, nor `vault`, nor `inventory`, and two independent tests hold that boundary.
- Release gates: a positive and a negative fixture per rule enforced by data, a canary of twenty secrets, determinism, stability over a volatile field, a mutation test, and `scripts/check_gates.py` as the gate of a release.
- Repository: the component moved into the `netops` monorepo layout under `components/netops-auditor/`, carries its own `pyproject.toml`, `LICENSE` copy, and release selector, and is covered by the repository gate `scripts/check_release.py`.
