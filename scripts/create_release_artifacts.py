#!/usr/bin/env python3
"""Export an allowlisted public tree and create deterministic release integrity metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.1.0"
EXACT = {
    ".github/workflows/ci.yml",
    ".dockerignore", ".gitignore", "CHANGELOG.md", "CONTRIBUTING.md", "Dockerfile",
    "LICENSE", "README.md", "SECURITY.md", "compose.yaml", "pyproject.toml",
    "requirements.txt", "requirements.lock", "requirements-release.in",
    "requirements-release.lock", "sbom.cdx.json",
}
DIRECTORIES = {"config", "docs", "src"}
TESTS = {
    "tests/run_tests.py", "tests/test_audit_rotation.py",
    "tests/test_plain_ftp_acknowledgement.py",
    "tests/test_proxy.py", "tests/test_security.py", "tests/test_sftp_safety.py",
    "tests/test_engine_safety.py",
    "tests/test_supply_chain.py", "tests/test_phase1_surface.py",
}
SCRIPTS = {
    "scripts/check_public_release.py", "scripts/create_release_artifacts.py",
    "scripts/generate_sbom.py", "scripts/proxy_sanitize.py", "scripts/remote_mcp_proxy.py",
}


def selected_files(root: Path = ROOT) -> list[Path]:
    chosen: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        relative = path.relative_to(root).as_posix()
        if (
            relative in EXACT or relative in TESTS or relative in SCRIPTS
            or relative.split("/", 1)[0] in DIRECTORIES
        ):
            if (
                relative.startswith(("config/container/certs/", "config/container/ca/"))
                and path.name != ".gitkeep"
            ):
                continue
            if relative == "config/target-policy.json":
                continue
            if relative.startswith("docs/") and "audit" in Path(relative).stem:
                continue
            chosen.append(path)
    return sorted(chosen, key=lambda item: item.relative_to(root).as_posix())


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--image-digest")
    args = parser.parse_args()
    if args.image_digest and not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image_digest):
        parser.error("--image-digest must be sha256:<64 lowercase hex digits>")

    destination = args.output.resolve() / f"netops-helper-{VERSION}"
    if destination.exists():
        shutil.rmtree(destination)
    for source in selected_files():
        relative = source.relative_to(ROOT)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        target.chmod(0o755 if relative.as_posix() in SCRIPTS else 0o644)

    from_line = (destination / "Dockerfile").read_text().splitlines()[0]
    base_digest = from_line.rsplit("@", 1)[1]
    entries = {
        path.relative_to(destination).as_posix(): digest(path)
        for path in sorted(destination.rglob("*")) if path.is_file()
    }
    manifest = {
        "schema": 1,
        "name": "netops-helper",
        "version": VERSION,
        "base_image_digest": base_digest,
        "image_digest": args.image_digest,
        "files": entries,
    }
    manifest_path = destination / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    manifest_path.chmod(0o644)

    checksum_entries = {**entries, "release-manifest.json": digest(manifest_path)}
    sums = "".join(f"{value}  {name}\n" for name, value in sorted(checksum_entries.items()))
    (destination / "SHA256SUMS").write_text(sums)
    (destination / "SHA256SUMS").chmod(0o644)

    completed = subprocess.run(
        [sys.executable, "-B", str(destination / "scripts/check_public_release.py"), str(destination)],
        check=False,
    )
    if completed.returncode:
        return completed.returncode
    bytecode = [
        path for path in destination.rglob("*")
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}
    ]
    if bytecode:
        print("release_export=failed detail=python bytecode present", file=sys.stderr)
        return 1
    print(f"release_export=complete files={len(entries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
