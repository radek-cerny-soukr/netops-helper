from pathlib import Path


ROOT = Path(__file__).parents[1]
VENDOR_MARKERS = ("co" + "dex", "open" + "ai", "chat" + "gpt", "clau" + "de", "anthro" + "pic")
WRITE_MARKERS = (
    "prepare_", "apply_", "cancel_change", "sftp_upload",
    "send_command_timing", "posix_rename", "save_config", "config_mode",
)


def test_distribution_is_agent_vendor_neutral() -> None:
    assert not (ROOT / "plugin").exists()
    public_paths = "\n".join(path.relative_to(ROOT).as_posix().lower() for path in ROOT.rglob("*"))
    for marker in VENDOR_MARKERS:
        assert marker not in public_paths


def test_phase1_source_has_no_write_implementation() -> None:
    source_root = ROOT / "src" / "netops_helper"
    assert not (source_root / "changes.py").exists()
    assert not (source_root / "policy.py").exists()
    source = "\n".join(path.read_text().lower() for path in source_root.glob("*.py"))
    for marker in WRITE_MARKERS:
        assert marker not in source


def test_server_declares_read_only_untrusted_boundary() -> None:
    server = (ROOT / "src/netops_helper/server.py").read_text().lower()
    for required in ("read-only", "untrusted", "write_tools"):
        assert required in server


def test_docs_require_isolated_read_only_session() -> None:
    docs = (ROOT / "docs/security-model.md").read_text().lower()
    for required in ("untrusted", "dedicated", "read-only", "never instructions"):
        assert required in docs
