# Release process

Official releases are built locally on a trusted Raspberry Pi ARM64 host from a clean, signed
commit. GitHub-hosted CI performs portable source checks only; it is not the release builder.

Never publish the surrounding private workspace, environment-specific certificates, reports, live
tests, credentials, host keys, local policy, or deployment scripts. The release export is a positive
allowlist and deliberately excludes maintainer notes and internal review material.

1. Review every source change. Ensure the version agrees in `pyproject.toml`,
   changelog, and release tooling.
2. Regenerate both Python 3.12 hash locks with the reviewed `pip-tools` version, regenerate the
   CycloneDX dependency SBOM, and review the complete dependency/license diff.
3. In the isolated local builder, install `requirements-release.lock` with `--require-hashes`.
   Run pytest, dependency-free security tests, SBOM comparison, and
   `scripts/check_public_release.py`.
4. Create the allowlisted source tree with `scripts/create_release_artifacts.py`. The trusted host
   runs Docker Buildx only on this export; the release toolbox must not mount the host Docker socket.
5. Record the ARM64 OCI image digest, generate an image SBOM, scan it with a current vulnerability
   database, and stop the release on unreviewed critical findings. Exact reviewed exceptions and
   their residual risk are disclosed in [Known vulnerability findings](known-vulnerabilities.md).
6. Recreate the source export with the image digest, produce a deterministic source archive, and
   generate one SHA-256 manifest covering every published artifact.
7. Sign the commit and annotated Git tag, then sign the checksum manifest with Sigstore/cosign.
8. Push only the clean public repository and signed tag. Create a draft GitHub release and attach
   the source archive, ARM64 OCI archive, manifests, SBOMs, scan report, digest, checksums, and
   signature bundle.
9. Independently verify the draft and its signature before publishing it.

The maintained image for 0.1.0 is Linux ARM64. Cross-building amd64 is intentionally excluded
because it would require privileged host-level binfmt/QEMU setup. Users on other architectures can
review and build the source themselves, but those builds are outside the official verification
claim.

Changing an image digest, locked dependency, snapshot date, or release tool is a reviewed source
change. Pinning improves repeatability; it does not prove safety, so vulnerability, license, and
residual-risk review remain mandatory.
