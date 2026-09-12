from __future__ import annotations

import dataclasses
import json
import os
import traceback

import pytest

from netops_auditor import vault

CANARY = "KANARCI-TOKEN-NESMI-UNIKNOUT"
NAME = "fw-lab-token"
DUMMY = "replace-me"


def _doc(value=CANARY, kind="api-token", name=NAME, version=1):
    return {"version": version, "credentials": {name: {"kind": kind, "value": value}}}


def _write(tmp_path, document, mode=0o600, filename="vault.json"):
    path = tmp_path / filename
    if isinstance(document, bytes):
        path.write_bytes(document)
    elif isinstance(document, str):
        path.write_text(document, encoding="utf-8")
    else:
        path.write_text(json.dumps(document), encoding="utf-8")
    os.chmod(path, mode)
    return path


def _loaded(tmp_path):
    return vault.load(_write(tmp_path, _doc()))


def _shown(error) -> tuple:
    return (
        str(error),
        repr(error),
        "".join(traceback.format_exception(type(error), error, error.__traceback__)),
    )


def test_load_returns_vault_with_credential(tmp_path):
    loaded = _loaded(tmp_path)
    assert isinstance(loaded, vault.Vault)
    credential = loaded.credential(NAME)
    assert isinstance(credential, vault.Credential)
    assert credential.name == NAME
    assert credential.kind == "api-token"


def test_use_is_the_way_to_the_value(tmp_path):
    assert _loaded(tmp_path).credential(NAME).use() == CANARY


def test_names_are_sorted(tmp_path):
    document = {
        "version": 1,
        "credentials": {
            "zeta": {"kind": "api-token", "value": DUMMY},
            "alfa": {"kind": "api-token", "value": DUMMY},
            "mezi": {"kind": "api-token", "value": DUMMY},
        },
    }
    loaded = vault.load(_write(tmp_path, document))
    assert loaded.names() == ("alfa", "mezi", "zeta")


def test_names_of_empty_vault(tmp_path):
    loaded = vault.load(_write(tmp_path, {"version": 1, "credentials": {}}))
    assert loaded.names() == ()


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_strict_mode_is_accepted(tmp_path, mode):
    path = _write(tmp_path, _doc(), mode=mode)
    assert vault.load(path).names() == (NAME,)


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660, 0o606, 0o666, 0o700, 0o755, 0o777, 0o602])
def test_loose_mode_is_refused(tmp_path, mode):
    path = _write(tmp_path, _doc(), mode=mode)
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    message = str(caught.value)
    assert "mode" in message
    assert str(path) in message
    for text in _shown(caught.value):
        assert CANARY not in text


def test_symlink_to_loose_file_is_refused(tmp_path):
    target = _write(tmp_path, _doc(), mode=0o644, filename="target.json")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(vault.VaultError) as caught:
        vault.load(link)
    assert "mode" in str(caught.value)
    for text in _shown(caught.value):
        assert CANARY not in text


def test_symlink_to_strict_file_is_accepted(tmp_path):
    target = _write(tmp_path, _doc(), mode=0o600, filename="target.json")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    assert vault.load(link).credential(NAME).use() == CANARY


def test_missing_file_names_the_path(tmp_path):
    path = tmp_path / "chybi.json"
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    message = str(caught.value)
    assert str(path) in message
    assert "does not exist" in message


def test_broken_symlink_names_the_path(tmp_path):
    link = tmp_path / "link.json"
    link.symlink_to(tmp_path / "chybi.json")
    with pytest.raises(vault.VaultError) as caught:
        vault.load(link)
    assert str(link) in str(caught.value)


def test_repr_and_str_hide_the_value(tmp_path):
    loaded = _loaded(tmp_path)
    credential = loaded.credential(NAME)
    holder = credential.__dict__["_secret"]
    rendered = (
        repr(credential),
        str(credential),
        format(credential),
        "%s" % (credential,),
        f"{credential}",
        repr(loaded),
        str(loaded),
        f"{loaded}",
        repr([credential]),
        repr({NAME: credential}),
        repr(credential.__dict__),
        repr(vars(credential)),
        repr(loaded.__dict__),
        repr(holder),
        str(holder),
        repr(dataclasses.asdict(credential)),
        json.dumps(dataclasses.asdict(credential)),
    )
    for text in rendered:
        assert CANARY not in text
    assert NAME in repr(credential)
    assert NAME in repr(loaded)
    assert vault.HIDDEN in repr(credential.__dict__)


def test_value_is_not_a_dataclass_field():
    assert tuple(item.name for item in dataclasses.fields(vault.Credential)) == ("name", "kind")


def test_no_public_attribute_holds_the_value(tmp_path):
    credential = _loaded(tmp_path).credential(NAME)
    for attribute in dir(credential):
        if attribute.startswith("_"):
            continue
        assert getattr(credential, attribute) != CANARY


def test_asdict_does_not_carry_the_value(tmp_path):
    credential = _loaded(tmp_path).credential(NAME)
    assert dataclasses.asdict(credential) == {"name": NAME, "kind": "api-token"}


def _broken():
    return {
        "bad-version": _doc(version=2),
        "version-as-text": _doc(version="1"),
        "version-as-bool": _doc(version=True),
        "unknown-document-field": dict(_doc(), extra=True),
        "missing-credentials": {"version": 1},
        "missing-version": {"credentials": {}},
        "document-not-object": [_doc()],
        "credentials-not-object": {"version": 1, "credentials": [{"kind": "api-token", "value": CANARY}]},
        "entry-not-object": {"version": 1, "credentials": {NAME: CANARY}},
        "entry-unknown-field": {
            "version": 1,
            "credentials": {NAME: {"kind": "api-token", "value": CANARY, "token": CANARY}},
        },
        "entry-missing-kind": {"version": 1, "credentials": {NAME: {"value": CANARY}}},
        "entry-missing-value": {"version": 1, "credentials": {NAME: {"kind": "api-token"}}},
        "unknown-kind": _doc(kind="ssh-password"),
        "kind-holds-the-value": _doc(kind=CANARY),
        "empty-name": _doc(name=""),
        "blank-name": _doc(name="   "),
        "empty-value": _doc(value=""),
        "blank-value": _doc(value="   "),
        "value-as-int": _doc(value=12345),
        "value-as-bool": _doc(value=True),
        "value-as-null": _doc(value=None),
        "value-as-list": _doc(value=[CANARY]),
        "value-as-object": _doc(value={"token": CANARY}),
    }


@pytest.mark.parametrize("case", sorted(_broken()))
def test_document_error_paths_hide_the_value(tmp_path, case):
    path = _write(tmp_path, _broken()[case])
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    for text in _shown(caught.value):
        assert CANARY not in text


@pytest.mark.parametrize(
    "case, fragment",
    [
        ("bad-version", "version must be 1"),
        ("version-as-bool", "version must be 1"),
        ("unknown-document-field", "unknown document fields: extra"),
        ("missing-credentials", "missing document fields: credentials"),
        ("document-not-object", "must hold an object, got list"),
        ("credentials-not-object", "credentials must be an object, got list"),
        ("entry-not-object", "must be an object, got str"),
        ("entry-unknown-field", "unknown fields: token"),
        ("entry-missing-kind", "missing fields: kind"),
        ("unknown-kind", "kind must be one of: api-token"),
        ("kind-holds-the-value", "kind must be one of: api-token"),
        ("empty-value", "value must be a non-empty string, got str"),
        ("value-as-int", "value must be a non-empty string, got int"),
        ("value-as-null", "value must be a non-empty string, got NoneType"),
        ("empty-name", "credential names must be non-empty strings"),
    ],
)
def test_document_error_messages_are_explicit(tmp_path, case, fragment):
    path = _write(tmp_path, _broken()[case])
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    assert fragment in str(caught.value)
    assert str(path) in str(caught.value)


def test_invalid_json_hides_the_value(tmp_path):
    path = _write(tmp_path, json.dumps(_doc())[:-2])
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    assert "not valid JSON" in str(caught.value)
    for text in _shown(caught.value):
        assert CANARY not in text


def test_not_utf8_hides_the_value(tmp_path):
    path = _write(tmp_path, json.dumps(_doc()).encode("utf-8") + b"\xff")
    with pytest.raises(vault.VaultError) as caught:
        vault.load(path)
    assert "not valid UTF-8" in str(caught.value)
    for text in _shown(caught.value):
        assert CANARY not in text


def test_unknown_credential_lists_known_names(tmp_path):
    loaded = _loaded(tmp_path)
    with pytest.raises(vault.VaultError) as caught:
        loaded.credential("neznamy")
    message = str(caught.value)
    assert "unknown credential" in message
    assert "neznamy" in message
    assert NAME in message
    for text in _shown(caught.value):
        assert CANARY not in text


def test_unknown_credential_in_empty_vault(tmp_path):
    loaded = vault.load(_write(tmp_path, {"version": 1, "credentials": {}}))
    with pytest.raises(vault.VaultError) as caught:
        loaded.credential("neznamy")
    assert "known names: none" in str(caught.value)


@pytest.mark.parametrize("name", [None, 1, b"fw-lab-token", ["fw-lab-token"]])
def test_credential_name_must_be_string(tmp_path, name):
    loaded = _loaded(tmp_path)
    with pytest.raises(vault.VaultError) as caught:
        loaded.credential(name)
    assert "must be a string" in str(caught.value)
    for text in _shown(caught.value):
        assert CANARY not in text


@pytest.mark.parametrize("bad", ["", "   ", 1, None, True, [], {}])
def test_credential_rejects_bad_value(bad):
    with pytest.raises(vault.VaultError) as caught:
        vault.Credential(name=NAME, kind="api-token", value=bad)
    assert "value must be a non-empty string" in str(caught.value)


def test_credential_rejects_unknown_kind():
    with pytest.raises(vault.VaultError) as caught:
        vault.Credential(name=NAME, kind="ssh-password", value=DUMMY)
    assert "kind must be one of: api-token" in str(caught.value)


@pytest.mark.parametrize("bad", ["", "   ", None, 7])
def test_credential_rejects_bad_name(bad):
    with pytest.raises(vault.VaultError) as caught:
        vault.Credential(name=bad, kind="api-token", value=DUMMY)
    assert "credential name must be a non-empty string" in str(caught.value)


def test_credential_error_hides_the_value():
    with pytest.raises(vault.VaultError) as caught:
        vault.Credential(name=NAME, kind="ssh-password", value=CANARY)
    for text in _shown(caught.value):
        assert CANARY not in text
