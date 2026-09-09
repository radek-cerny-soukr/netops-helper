#!/usr/bin/env python3
"""Generate a reproducible CycloneDX SBOM and connect the root to direct dependencies."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "sbom.cdx.json"


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def direct_names() -> set[str]:
    result = set()
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if entry and not entry.startswith("#"):
            result.add(canonical(re.split(r"[<=>!~\[]", entry, maxsplit=1)[0]))
    return result


def main() -> int:
    subprocess.run([
        sys.executable, "-m", "cyclonedx_py", "requirements", str(ROOT / "requirements.lock"),
        "--pyproject", str(ROOT / "pyproject.toml"), "--mc-type", "application",
        "--sv", "1.6", "--output-reproducible", "--of", "JSON", "-o", str(OUTPUT),
    ], check=True)
    document = json.loads(OUTPUT.read_text(encoding="utf-8"))
    root = document["metadata"]["component"]
    direct = direct_names()
    references = sorted(
        component["bom-ref"] for component in document.get("components", [])
        if canonical(component.get("name", "")) in direct
    )
    if len(references) != len(direct):
        raise RuntimeError("SBOM is missing one or more direct dependencies")
    root_dependency = next(
        item for item in document.get("dependencies", []) if item.get("ref") == root["bom-ref"]
    )
    root_dependency["dependsOn"] = references
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"sbom_generation=complete components={len(document.get('components', []))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
