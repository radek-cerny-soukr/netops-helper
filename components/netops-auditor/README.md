# netops-auditor

Configuration audit for network devices. The auditor collects the configuration from the device itself, evaluates it against a catalogue of rules, and reports findings without ever carrying the configuration or a credential into its answers.

This component has not been released yet. It is usable from the CLI today, and its shape is fixed by its gates rather than by its documentation.

## What it does

- **Rules as data.** The catalogue is JSON: identifier, version, check, class (`fakt` or `usudek`), severity, evidence fields, remediation, and optional compliance references. A rule without a positive and a negative fixture does not enter the catalogue - the gate rejects it.
- **Collects its own configuration.** One channel per device, pinned in the inventory: `file`, `fortios-rest`, or `ssh`. There is no fallback ladder; a failing channel fails the collection and says why. What each channel cannot do is written down in [`docs/channels.md`](docs/channels.md).
- **Never changes a device.** Not a policy, not an interface, not even a console setting. With an active FortiOS pager the collection refuses instead of disabling it.
- **Keeps secrets out of findings.** A finding carries an object reference and line numbers, never the configuration text. A canary fixture with twenty marked secrets must not leak a single one into a finding, an MCP answer, or a CLI report.
- **Knows what changed.** Baseline in the database, suppressions with a mandatory expiry in a reviewed JSON file, four finding states, and a freshness threshold.
- **Read-only MCP surface.** Six tools over a store opened read-only. The server cannot reach a device: it imports neither the collection, nor the vault, nor the inventory.

## Running it

The auditor is standard library only. `fastmcp` is needed by the MCP surface alone and is pinned in `requirements-mcp.txt`; the CLI runs without it.

```sh
PYTHONPATH=src python3 -m netops_auditor --help
PYTHONPATH=src python3 -m pytest -q          # the test suite
python3 scripts/check_gates.py               # the gate of a release
```

## Boundaries

The auditor is not a compliance product: rules may carry `refs` to CIS, ZKB, or DORA, but no profile is built and no compliance is claimed. Rules exist for FortiOS only; EXOS can be collected but not yet evaluated, and that is a gap, not support. A finding of class `usudek` is a judgement and is never emitted at high severity.

MIT licensed. Part of the [`netops`](../../README.md) family.
