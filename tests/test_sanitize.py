#!/usr/bin/env python3
"""Dependency-free regression tests for contextual secret redaction."""

from __future__ import annotations

from netops_helper.sanitize import redact


def test_log_language_is_preserved() -> None:
    source = "sshd: Failed password for invalid user admin from host.invalid"
    assert redact(source) == source


def test_snmp_status_redacts_the_value_not_the_neighboring_word() -> None:
    source = "SNMP community string configured: public"
    cleaned = redact(source)
    assert cleaned == "SNMP community string configured: <REDACTED>"
    assert "public" not in cleaned


def test_legacy_whitespace_community_value_is_redacted() -> None:
    cleaned = redact("community private-community")
    assert cleaned == "community <REDACTED>"
    assert "private-community" not in cleaned


def test_structured_and_cli_secrets_are_redacted() -> None:
    source = (
        'password=hunter2 token: abc "secret": "quoted value"\n'
        "enable secret 5 hashvalue\n"
        "username reader password 7 encoded\n"
        "snmp-server community public RO"
    )
    cleaned = redact(source)
    for hidden in ("hunter2", "abc", "quoted value", "hashvalue", "encoded", "public"):
        assert hidden not in cleaned
    for context in ("password=", "token:", '"secret":', "enable secret 5", "username reader"):
        assert context in cleaned


def test_exact_injected_secrets_and_diagnostic_context() -> None:
    source = (
        "time=10:23:45 host=host.invalid serial=DEVICE123 "
        "credential material-is-secret"
    )
    cleaned = redact(source, secrets=("material-is-secret",))
    for visible in ("10:23:45", "host.invalid", "DEVICE123"):
        assert visible in cleaned
    assert "material-is-secret" not in cleaned


def test_redaction_limit_is_still_enforced() -> None:
    try:
        redact("x" * 20, limit=10)
    except ValueError as exc:
        assert "explicit limit" in str(exc)
    else:
        raise AssertionError("redaction limit was not enforced")


def main() -> int:
    test_log_language_is_preserved()
    test_snmp_status_redacts_the_value_not_the_neighboring_word()
    test_legacy_whitespace_community_value_is_redacted()
    test_structured_and_cli_secrets_are_redacted()
    test_exact_injected_secrets_and_diagnostic_context()
    test_redaction_limit_is_still_enforced()
    print("sanitize_tests=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
