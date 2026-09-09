#!/usr/bin/env python3
"""Fail closed when a public release contains local/private or mutable-build artifacts."""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {"", ".json", ".md", ".py", ".toml", ".txt", ".yaml", ".yml"}


def _tracked_release_files(root: Path) -> list[Path]:
    sys.path.insert(0, str(root / "scripts"))
    from create_release_artifacts import selected_files
    return selected_files(root)


def check(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    files = _tracked_release_files(root)
    forbidden_names = {"vault.json", "target-policy.json", "known_hosts"}
    private_markers = ("BEGIN " + "PRIVATE KEY", "/work" + "space/")
    topology_markers = ("fortigate" + "-mcp", "fortigate" + "-readonly", "rpi5" + "-master", "rpi5" + "-slave", "/home/" + "race")
    agent_vendor_markers = ("co" + "dex", "open" + "ai", "chat" + "gpt", "clau" + "de", "anthro" + "pic")
    private_ipv4 = re.compile(r"(?<![0-9])(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3})(?![0-9])")
    hardcoded_trust_file = re.compile(
        r"/(?:usr/local/share/ca-certificates|etc/netops-helper/certs)/[^\s\"'`]+\.(?:crt|cer|pem)"
    )
    for path in files:
        relative = path.relative_to(root)
        if any(marker in relative.as_posix().lower() for marker in agent_vendor_markers):
            errors.append(f"agent-vendor-specific path in {relative}")
        if path.name in forbidden_names:
            errors.append(f"private configuration included: {relative}")
        if path.suffix.lower() in {".crt", ".cer", ".key", ".p12", ".pfx", ".pem"}:
            errors.append(f"environment-specific key/certificate included: {relative}")
        if path.suffix.lower() in TEXT_SUFFIXES:
            text = path.read_text(encoding="utf-8", errors="replace")
            for marker in (*private_markers, *topology_markers, *agent_vendor_markers):
                if marker in text:
                    errors.append(f"private marker in {relative}")
            if private_ipv4.search(text):
                errors.append(f"private IPv4 address in {relative}")
            if hardcoded_trust_file.search(text):
                errors.append(f"hard-coded environment trust file in {relative}")

    for trust_directory in (root / "config/container/ca", root / "config/container/certs"):
        if trust_directory.exists():
            for trust_path in trust_directory.iterdir():
                if trust_path.is_file() and trust_path.name != ".gitkeep":
                    errors.append(f"environment-specific trust material present: {trust_path.relative_to(root)}")

    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    first = dockerfile.splitlines()[0]
    if not re.fullmatch(r"FROM python:[^@\s]+@sha256:[0-9a-f]{64}", first):
        errors.append("Dockerfile base image is not digest-pinned")
    if "pip install --no-cache-dir --upgrade" in dockerfile or "apt-get" in dockerfile:
        errors.append("Dockerfile contains a moving package-manager operation")
    if "--require-hashes -r requirements.lock" not in dockerfile:
        errors.append("Dockerfile does not enforce the dependency hash lock")

    for lock_name in ("requirements.lock", "requirements-release.lock"):
        lock = (root / lock_name).read_text(encoding="utf-8")
        active = "\n".join(
            line for line in lock.splitlines() if not line.lstrip().startswith("#")
        )
        if "--hash=sha256:" not in active:
            errors.append(f"{lock_name} does not enforce hashes")
        if any(marker in active for marker in ("http://", "file:", "--no-index", "--trusted-host")):
            errors.append(f"{lock_name} contains an unsafe package source")

    release_input = {
        line.strip() for line in (root / "requirements-release.in").read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    if release_input != {"-r requirements.txt", "cyclonedx-bom==7.3.1", "pytest==9.1.1"}:
        errors.append("requirements-release.in is not the reviewed release tool set")

    for workflow in (root / ".github" / "workflows").glob("*.yml"):
        for value in re.findall(r"^\s*uses:\s*(\S+)\s*(?:#.*)?$", workflow.read_text(), re.MULTILINE):
            if not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", value):
                errors.append(f"GitHub Action is not SHA-pinned in {workflow.name}: {value}")
    ci_workflow = (root / ".github" / "workflows" / "ci.yml").read_text()
    if "PYTHONPATH=src python tests/run_tests.py" not in ci_workflow:
        errors.append("CI dependency-free runner does not set PYTHONPATH=src")
    if (root / "plugin").exists():
        errors.append("agent-vendor-specific plugin directory is forbidden")
    source_root = root / "src" / "netops_helper"
    for removed_name in ("changes.py", "policy.py"):
        if (source_root / removed_name).exists():
            errors.append(f"phase-1 release contains removed write module: {removed_name}")
    forbidden_implementation = (
        "prepare" + "_", "apply" + "_", "cancel" + "_change", "sftp" + "_upload",
        "send" + "_command_timing", "posix" + "_rename", "save" + "_config", "config" + "_mode",
    )
    for source_path in source_root.glob("*.py"):
        source_text = source_path.read_text(encoding="utf-8").lower()
        if any(marker in source_text for marker in forbidden_implementation):
            errors.append(f"phase-1 source contains a write implementation: {source_path.name}")
    server_source = (root / "src/netops_helper/server.py").read_text()
    forbidden_surface = ("prepare" + "_", "apply" + "_", "cancel" + "_change")
    if any(marker in server_source for marker in forbidden_surface):
        errors.append("phase-1 MCP server contains a write tool surface")
    return errors


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT
    errors = check(root)
    if errors:
        for error in errors:
            print(f"public_release_check=failed detail={error}")
        return 1
    print("public_release_check=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
