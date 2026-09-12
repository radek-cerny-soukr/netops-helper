from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

SEVERITIES = ("high", "medium", "low", "info")
CLASSES = ("fakt", "usudek")
EVIDENCE_TYPES = (str, int, bool)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_version: int
    device: str
    object_key: str
    severity: str
    rule_class: str
    section: str
    line: int
    evidence: tuple = field(default_factory=tuple)

    def fingerprint(self) -> str:
        material = "\x1f".join((self.rule_id, str(self.rule_version), self.device, self.object_key))
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "device": self.device,
            "object_key": self.object_key,
            "severity": self.severity,
            "class": self.rule_class,
            "section": self.section,
            "line": self.line,
            "evidence": dict(self.evidence),
            "fingerprint": self.fingerprint(),
        }
