from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).parents[1]


def test_sbom_contains_all_direct_dependencies() -> None:
    document = json.loads((ROOT / "sbom.cdx.json").read_text())
    root = document["metadata"]["component"]
    dependency = next(item for item in document["dependencies"] if item["ref"] == root["bom-ref"])
    direct = {
        re.split(r"[<=>!~\[]", line.strip(), maxsplit=1)[0].replace("_", "-").lower()
        for line in (ROOT / "requirements.txt").read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    components = {
        item["bom-ref"]: item["name"].replace("_", "-").lower()
        for item in document["components"]
    }
    assert {components[reference] for reference in dependency["dependsOn"]} == direct


def test_release_license_is_mit() -> None:
    assert (ROOT / "LICENSE").read_text().startswith("MIT License\n")
    assert 'license = { text = "MIT" }' in (ROOT / "pyproject.toml").read_text()


def test_healthcheck_uses_system_trust_without_private_ca_name() -> None:
    source = (ROOT / "src/netops_helper/selftest.py").read_text()
    assert "get_default_verify_paths" in source
    assert "/usr/local/share/ca-certificates/" not in source


def test_base_image_is_pinned_and_lock_uses_hashes() -> None:
    first = (ROOT / "Dockerfile").read_text().splitlines()[0]
    assert re.fullmatch(r"FROM python:[^@\s]+@sha256:[0-9a-f]{64}", first)
    for name in ("requirements.lock", "requirements-release.lock"):
        lock = (ROOT / name).read_text()
        active = "\n".join(
            line for line in lock.splitlines() if not line.lstrip().startswith("#")
        )
        assert "pip-compile with Python 3.12" in lock
        assert "--hash=sha256:" in active
        assert "--no-index" not in active
        assert "--trusted-host" not in active
        assert "http://" not in active
        assert "file:" not in active


def test_release_tools_are_pinned() -> None:
    lines = {
        line.strip() for line in (ROOT / "requirements-release.in").read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert lines == {"-r requirements.txt", "cyclonedx-bom==7.3.1", "pytest==9.1.1"}



def test_github_actions_use_full_commit_shas() -> None:
    for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
        for value in re.findall(r"^\s*uses:\s*(\S+)\s*(?:#.*)?$", workflow.read_text(), re.MULTILINE):
            assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", value), (workflow, value)




def test_ci_dependency_free_runner_uses_source_tree() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "PYTHONPATH=src python tests/run_tests.py" in workflow


def test_public_export_contains_no_python_bytecode(tmp_path: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            "-B",
            str(ROOT / "scripts/create_release_artifacts.py"),
            "--output",
            str(tmp_path),
        ],
        check=True,
    )
    exported = tmp_path / "netops-helper-0.1.0"
    assert not [path for path in exported.rglob("*") if "__pycache__" in path.parts]
    assert not list(exported.rglob("*.pyc"))
    assert not list(exported.rglob("*.pyo"))
