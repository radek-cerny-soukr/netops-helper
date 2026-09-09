# Contributing

Contributions are welcome when they preserve the fail-closed model.

1. Open an issue describing the use case and threat impact before adding a new mutation profile.
2. Keep credentials, addresses, host keys, certificates, device output, and local policies out of
   commits, fixtures, issues, and CI logs.
3. Add exact positive and negative tests for every command/path capability.
4. Run the complete offline suite and public-release checker.
5. Regenerate `requirements.lock` and `sbom.cdx.json` only with the pinned release tooling, and
   explain dependency changes in the pull request.
6. Update tool, limitation, security, and changelog documentation with behavior changes.

Do not add raw command input, a generic-shell escape hatch, automatic host-key acceptance, write tools, or broad credentials to phase 1. New queries require named templates, typed inventory-bound slots, positive and negative tests, explicit pagination, and review of prompt-injection exposure. Device-side read-only authorization is mandatory; redaction and skill instructions are not authorization boundaries.

By submitting a contribution, you agree that it is licensed under the MIT License.
