from __future__ import annotations

import importlib.util
import ipaddress
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).parents[1]
GENERATOR_PATH = ROOT / "scripts" / "generate_egress_rules.py"
CHECKER_PATH = ROOT / "scripts" / "check_egress_rules.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


generator = _load("generate_egress_rules", GENERATOR_PATH)
checker = _load("check_egress_rules", CHECKER_PATH)
RFC1918_TEST_LAN = str(ipaddress.ip_network((0x0A000000, 24)))

CGNAT_NETWORK_SAMPLE = str(ipaddress.ip_address(0x64400000))
RFC1918_TEST_ALPHA = str(ipaddress.ip_address(0x0A00000A))
RFC1918_TEST_BETA = str(ipaddress.ip_address(0x0A000014))
RFC1918_TEST_BLOCKS = tuple(ipaddress.ip_network(value) for value in (
    (0x0A000000, 8), (0xAC100000, 12), (0xC0A80000, 16),
))


def fixture(profile: str = "strict-target") -> tuple[dict, dict]:
    vault = {
        "netops-runner": {
            "host": "runner.example.invalid",
            "port": 22,
            "login": "runner-login-value",
            "password": "runner-password-value",
        },
        "device-alpha": {
            "host": RFC1918_TEST_ALPHA if profile == "lan-constrained" else "192.0.2.10",
            "port": 22,
            "login": "alpha-login-value",
            "password": "alpha-password-value",
        },
        "device-beta": {
            "host": "switch.example.invalid",
            "port": 2222,
            "login": "beta-login-value",
            "password": "beta-password-value",
        },
        "unrelated-secret-record": {
            "host": "unrelated.example.invalid",
            "port": 65000,
            "login": "unrelated-login-value",
            "password": "unrelated-password-value",
        },
    }
    policy = {
        "_egress": {
            "schema_version": 1,
            "profile": profile,
            "backend": "iptables",
            "bridge_name": "nh-egress0",
            "network_name": "netops-helper",
            "ipv6_mode": "deny",
            "dns_resolvers": ["203.0.113.53", "203.0.113.5"],
            "lan_cidrs": [RFC1918_TEST_LAN] if profile == "lan-constrained" else [],
        },
        "device-alpha": {
            "account_role": "read-only",
            "ssh_platform": "fortios",
            "enabled_queries": ["system_status"],
            "sftp_roots": [],
            "egress": {
                "addresses": [RFC1918_TEST_ALPHA if profile == "lan-constrained" else "192.0.2.10"],
                "tcp_ports": [8443],
                "udp_ports": [161],
                "tcp_port_ranges": [[50000, 50010]],
                "udp_port_ranges": [],
                "allow_icmp": True,
                "allow_dns": False,
                "tls_server_names": ["status.device.invalid"],
            },
        },
        "device-beta": {
            "account_role": "read-only",
            "ssh_platform": None,
            "enabled_queries": [],
            "sftp_roots": [],
            "egress": {
                "addresses": [RFC1918_TEST_BETA if profile == "lan-constrained" else "192.0.2.20"],
                "tcp_ports": [],
                "udp_ports": [1161],
                "tcp_port_ranges": [],
                "udp_port_ranges": [],
                "allow_icmp": False,
                "allow_dns": True,
                "tls_server_names": ["switch.example.invalid"],
            },
        },
    }
    return vault, policy


def observed_state(bundle: dict) -> dict:
    ruleset = bundle["ruleset"]
    ipv4 = "\n".join([
        "-A FORWARD -j DOCKER-USER",
        ruleset["ipv4"]["jump_rule"],
        *ruleset["ipv4"]["chain_rules"],
    ])
    return {
        "backend": "iptables",
        "network_name": "netops-helper",
        "network_driver": "bridge",
        "network_bridge": "nh-egress0",
        "network_ipv6_enabled": False,
        "bridge_names": ["lo", "nh-egress0"],
        "ipv4_save": ipv4,
    }


class GeneratorTests(unittest.TestCase):
    def test_icmp_rule_uses_iptables_save_numeric_type(self) -> None:
        vault, policy = fixture()
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        rules = bundle["ruleset"]["ipv4"]["chain_rules"]
        icmp_rules = [rule for rule in rules if " -p icmp " in rule]
        self.assertEqual(
            icmp_rules,
            [f"-A {generator.CHAIN_NAME} -d 192.0.2.10/32 -p icmp -m icmp --icmp-type 8 -j ACCEPT"],
        )
        self.assertFalse(any("echo-request" in rule for rule in rules))
        self.assertEqual(checker.check(bundle, observed_state(bundle)), [])

    def test_strict_bundle_contains_only_non_secret_scope(self) -> None:
        vault, policy = fixture()
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        encoded = generator.canonical_json(bundle).decode()
        for forbidden in (
            "device-alpha", "device-beta", "unrelated-secret-record",
            "alpha-login-value", "alpha-password-value", "beta-password-value",
            "runner-password-value", "unrelated-password-value", "example.invalid",
            "status.device.invalid", "switch.example.invalid", "tls_server_names",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertIn("192.0.2.10", encoded)
        self.assertIn("192.0.2.20", encoded)
        rules = bundle["ruleset"]["ipv4"]["chain_rules"]
        self.assertTrue(any("--dport 22 " in rule and "192.0.2.10/32" in rule for rule in rules))
        self.assertTrue(any("--dport 8443 " in rule and "192.0.2.10/32" in rule for rule in rules))
        self.assertFalse(any("--dport 443 " in rule for rule in rules))
        self.assertTrue(any("--dport 50000:50010 " in rule for rule in rules))
        self.assertFalse(any("--dport 2222 " in rule for rule in rules))
        self.assertTrue(bundle["manifest"]["allow_dns"])
        self.assertEqual(bundle["bundle_schema"], 3)
        self.assertIs(bundle["manifest"]["network_ipv6_enabled"], False)
        self.assertEqual(
            bundle["manifest"]["ipv6_boundary"],
            "docker-network-disabled",
        )
        self.assertNotIn("ipv6_mode", bundle["manifest"])
        self.assertEqual(
            set(bundle["ruleset"]),
            {"backend", "chain", "ipv4"},
        )
        self.assertNotIn('"ipv6":', encoded)
        self.assertNotIn("ip6tables", encoded)

    def test_lan_profile_uses_union_only_inside_explicit_lan(self) -> None:
        vault, policy = fixture("lan-constrained")
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        rules = bundle["ruleset"]["ipv4"]["chain_rules"]
        self.assertFalse(any("--dport 2222 " in rule for rule in rules))
        self.assertTrue(any(f"-d {RFC1918_TEST_LAN}" in rule and "--dport 161 " in rule for rule in rules))
        self.assertFalse(any(f"{RFC1918_TEST_ALPHA}/32" in rule for rule in rules))

    def test_lan_profile_rejects_target_outside_each_declared_private_block(self) -> None:
        for index, declared_lan in enumerate(RFC1918_TEST_BLOCKS):
            outside_lan = RFC1918_TEST_BLOCKS[(index + 1) % len(RFC1918_TEST_BLOCKS)]
            enrolled_address = str(declared_lan.network_address + 1)
            outside_address = str(outside_lan.network_address + 1)
            vault, policy = fixture("lan-constrained")
            policy["_egress"]["lan_cidrs"] = [str(declared_lan)]
            vault["device-alpha"]["host"] = outside_address
            policy["device-alpha"]["egress"]["addresses"] = [outside_address]
            policy["device-beta"]["egress"]["addresses"] = [enrolled_address]
            with self.subTest(declared_lan=str(declared_lan)):
                with self.assertRaisesRegex(
                    generator.EgressContractError,
                    "target is outside the declared LAN scope",
                ):
                    generator.build_bundle(vault, policy, "netops-runner")

    def test_lan_profile_rejects_every_non_rfc1918_scope(self) -> None:
        invalid = (
            "0.0.0.0/0", str(ipaddress.ip_network((0x0A000000, 7))),
            CGNAT_NETWORK_SAMPLE + "/10", "192.0.2.0/24", "224.0.0.0/4",
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(generator.EgressContractError):
                    generator._ipv4_network(value)
        valid = tuple(str(ipaddress.ip_network(value)) for value in (
            (0x0A000000, 8), (0x0A141E00, 24), (0xAC100000, 12),
            (0xAC1FFF00, 24), (0xC0A80000, 16),
        ))
        for value in valid:
            with self.subTest(value=value):
                self.assertEqual(generator._ipv4_network(value), value)

    def test_compose_explicitly_disables_network_ipv6(self) -> None:
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        network = compose.split("networks:\n", 2)[-1]
        self.assertIn("    enable_ipv6: false\n", network)
        self.assertIn("com.docker.network.bridge.name: nh-egress0", network)

    def test_authoritative_inventory_validation_fails_closed(self) -> None:
        invalid_inventory = (
            {"interfaces": ["Ethernet1/1;show"]},
            {"services": ["sshd --now"]},
            {"addresses": ["2001:0db8::10"]},
            {"addresses": ["192.0.002.10"]},
            {"switches": ["switch|show"]},
        )
        for inventory in invalid_inventory:
            vault, policy = fixture()
            policy["device-alpha"]["read_inventory"] = inventory
            with self.subTest(category=next(iter(inventory))):
                with self.assertRaises(generator.EgressContractError):
                    generator.build_bundle(vault, policy, "netops-runner")

        vault, policy = fixture()
        policy["device-alpha"]["read_inventory"] = {
            "interfaces": ["Ethernet1/1"],
            "services": ["sshd.service"],
            "addresses": ["2001:db8::10"],
            "switches": ["switch-1"],
        }
        generator.build_bundle(vault, policy, "netops-runner")

    def test_all_platform_aliases_accept_a_known_authoritative_query(self) -> None:
        self.assertEqual(
            generator.SUPPORTED_SSH_PLATFORMS,
            set(generator.PLATFORM_MAP),
        )
        for alias, canonical in generator.PLATFORM_MAP.items():
            vault, policy = fixture()
            policy["device-alpha"]["ssh_platform"] = alias
            policy["device-alpha"]["enabled_queries"] = [
                next(iter(generator.READ_QUERIES[canonical]))
            ]
            with self.subTest(alias=alias, canonical=canonical):
                generator.build_bundle(vault, policy, "netops-runner")

    def test_ipv6_and_unscoped_hostname_fail_closed(self) -> None:
        vault, policy = fixture()
        vault["device-alpha"]["host"] = "2001:db8::10"
        policy["device-alpha"]["egress"]["addresses"] = ["192.0.2.10"]
        with self.assertRaises(generator.EgressContractError):
            generator.build_bundle(vault, policy, "netops-runner")
        vault, policy = fixture()
        policy["device-beta"]["egress"]["addresses"] = []
        with self.assertRaises(generator.EgressContractError):
            generator.build_bundle(vault, policy, "netops-runner")

    def test_hostname_requires_addresses_dns_permission_and_resolver(self) -> None:
        vault, policy = fixture()
        policy["device-beta"]["egress"]["allow_dns"] = False
        with self.assertRaises(generator.EgressContractError):
            generator.build_bundle(vault, policy, "netops-runner")
        vault, policy = fixture()
        policy["_egress"]["dns_resolvers"] = []
        with self.assertRaises(generator.EgressContractError):
            generator.build_bundle(vault, policy, "netops-runner")

    def test_credential_port_is_only_derived_for_active_ssh_or_sftp(self) -> None:
        vault, policy = fixture()
        policy["device-alpha"]["enabled_queries"] = []
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        alpha = next(scope for scope in bundle["manifest"]["targets"] if "192.0.2.10" in scope["destinations"])
        self.assertNotIn(22, alpha["tcp_ports"])
        policy["device-alpha"]["sftp_roots"] = ["/safe"]
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        alpha = next(scope for scope in bundle["manifest"]["targets"] if "192.0.2.10" in scope["destinations"])
        self.assertIn(22, alpha["tcp_ports"])

    def test_dns_rules_require_an_enrolled_dns_consumer(self) -> None:
        vault, policy = fixture()
        vault["device-beta"]["host"] = "192.0.2.20"
        policy["device-beta"]["egress"]["allow_dns"] = False
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        self.assertFalse(bundle["manifest"]["allow_dns"])
        self.assertFalse(any("--dport 53 " in rule for rule in bundle["ruleset"]["ipv4"]["chain_rules"]))

    def test_exact_egress_and_global_contracts_fail_closed(self) -> None:
        vault, policy = fixture()
        policy["device-alpha"]["egress"]["unexpected"] = True
        with self.assertRaises(generator.EgressContractError):
            generator.build_bundle(vault, policy, "netops-runner")
        vault, policy = fixture()
        del policy["device-alpha"]["egress"]["tls_server_names"]
        with self.assertRaises(generator.EgressContractError):
            generator.build_bundle(vault, policy, "netops-runner")
        vault, policy = fixture()
        policy["device-alpha"]["egress"]["tls_server_names"] = ["*.device.invalid"]
        with self.assertRaises(generator.EgressContractError):
            generator.build_bundle(vault, policy, "netops-runner")
        vault, policy = fixture()
        policy["_egress"]["unexpected"] = True
        with self.assertRaises(generator.EgressContractError):
            generator.build_bundle(vault, policy, "netops-runner")
        vault, policy = fixture()
        del policy["_egress"]["ipv6_mode"]
        with self.assertRaises(generator.EgressContractError):
            generator.build_bundle(vault, policy, "netops-runner")

    def test_target_policy_envelope_rejects_unknown_and_missing_required_keys(self) -> None:
        vault, policy = fixture()
        policy["device-alpha"]["unexpected"] = True
        with self.assertRaises(generator.EgressContractError):
            generator.build_bundle(vault, policy, "netops-runner")
        for required in ("account_role", "ssh_platform", "enabled_queries", "egress"):
            vault, policy = fixture()
            del policy["device-alpha"][required]
            with self.subTest(required=required):
                with self.assertRaises(generator.EgressContractError):
                    generator.build_bundle(vault, policy, "netops-runner")

    def test_sftp_root_invalid_corpus_fails_before_credential_port_enrollment(self) -> None:
        invalid_roots = (
            "relative/path", "/", "//safe", "/safe/../etc", "/safe/\x00file",
            "/" + "x" * 2_000,
        )
        for root in invalid_roots:
            vault, policy = fixture()
            policy["device-alpha"]["sftp_roots"] = [root]
            with self.subTest(root_length=len(root)):
                with self.assertRaises(generator.EgressContractError):
                    generator.build_bundle(vault, policy, "netops-runner")

    def test_legacy_https_body_read_field_is_rejected_without_port_derivation(self) -> None:
        vault, policy = fixture()
        policy["device-alpha"]["https_endpoints"] = [{
            "path": "/export.conf", "port": 443, "use_basic_auth": False,
        }]
        with self.assertRaises(generator.EgressContractError):
            generator.build_bundle(vault, policy, "netops-runner")

    def test_explicit_and_effective_ports_must_not_overlap_ranges(self) -> None:
        vault, policy = fixture()
        policy["device-alpha"]["egress"]["tcp_port_ranges"] = [[8_000, 9_000]]
        with self.assertRaises(generator.EgressContractError):
            generator.build_bundle(vault, policy, "netops-runner")
        vault, policy = fixture()
        policy["device-alpha"]["egress"]["udp_port_ranges"] = [[160, 162]]
        with self.assertRaises(generator.EgressContractError):
            generator.build_bundle(vault, policy, "netops-runner")
        vault, policy = fixture()
        policy["device-alpha"]["egress"]["tcp_ports"] = []
        policy["device-alpha"]["egress"]["tcp_port_ranges"] = [[20, 30]]
        with self.assertRaises(generator.EgressContractError):
            generator.build_bundle(vault, policy, "netops-runner")

    def test_generate_is_atomic_mode_600_and_does_not_replace_inputs(self) -> None:
        vault, policy = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault_path = root / "vault.json"
            policy_path = root / "policy.json"
            output_path = root / "egress.json"
            vault_path.write_text(json.dumps(vault), encoding="utf-8")
            vault_path.chmod(0o600)
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            output_path.write_text("old", encoding="utf-8")
            output_path.chmod(0o644)
            generator.generate(vault_path, policy_path, output_path, "netops-runner")
            self.assertEqual(stat.S_IMODE(output_path.stat().st_mode), 0o600)
            bundle = json.loads(output_path.read_text(encoding="utf-8"))
            checker.validate_bundle(bundle)
            with self.assertRaises(generator.EgressContractError):
                generator.generate(vault_path, policy_path, vault_path, "netops-runner")

    def test_cli_failure_never_prints_input_values(self) -> None:
        vault, policy = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault_path = root / "vault.json"
            policy_path = root / "policy.json"
            output_path = root / "egress.json"
            vault_path.write_text(json.dumps(vault), encoding="utf-8")
            vault_path.chmod(0o644)
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-B", str(GENERATOR_PATH), "--vault", str(vault_path),
                 "--policy", str(policy_path), "--output", str(output_path)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(completed.stderr, "egress_generation=failed\n")
            self.assertFalse(output_path.exists())


class CheckerTests(unittest.TestCase):
    def test_checker_requires_docker_user_jump_to_be_first_in_forward(self) -> None:
        vault, policy = fixture()
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        state = observed_state(bundle)
        state["ipv4_save"] = "-A FORWARD -i nh-egress0 -j ACCEPT\n" + state["ipv4_save"]
        self.assertIn("ipv4_docker_user_unreachable", checker.check(bundle, state))
        state["ipv4_save"] = state["ipv4_save"].replace(
            "-A FORWARD -i nh-egress0 -j ACCEPT\n", "",
        ) + "\n-A FORWARD -j ACCEPT"
        self.assertNotIn("ipv4_docker_user_unreachable", checker.check(bundle, state))

    def test_checker_accepts_ipv6_disabled_network_and_ipv4_guard(self) -> None:
        vault, policy = fixture()
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        self.assertEqual(checker.check(bundle, observed_state(bundle)), [])

    def test_live_inspection_reads_false_and_never_calls_ip6tables(self) -> None:
        vault, policy = fixture()
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        commands: list[tuple[str, ...]] = []

        def fake_run(command: list[str]) -> str:
            commands.append(tuple(command))
            if command[:3] == ["docker", "network", "inspect"]:
                return json.dumps([{
                    "Driver": "bridge",
                    "EnableIPv6": False,
                    "Options": {"com.docker.network.bridge.name": "nh-egress0"},
                }])
            if command[:3] == ["nft", "list", "tables"]:
                return "table inet filter"
            if command == ["iptables-save"]:
                return observed_state(bundle)["ipv4_save"]
            raise AssertionError(f"unexpected command: {command!r}")

        class FakePath:
            def __init__(self, _value: str) -> None:
                pass

            def iterdir(self):
                return [type("Interface", (), {"name": "nh-egress0"})()]

        with mock.patch.object(checker, "_run", side_effect=fake_run), mock.patch.object(
            checker, "Path", FakePath,
        ):
            inspected = checker.inspect_live_state(bundle)
        self.assertEqual(checker.check(bundle, inspected), [])
        self.assertFalse(any(command[0].startswith("ip6tables") for command in commands))

    def test_live_inspection_rejects_missing_enable_ipv6(self) -> None:
        vault, policy = fixture()
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        with mock.patch.object(
            checker,
            "_run",
            return_value=json.dumps([{
                "Driver": "bridge",
                "Options": {"com.docker.network.bridge.name": "nh-egress0"},
            }]),
        ):
            with self.assertRaises(checker.EgressCheckError):
                checker.inspect_live_state(bundle)

    def test_live_inspection_does_not_fallback_when_nft_inspection_fails(self) -> None:
        vault, policy = fixture()
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        commands: list[tuple[str, ...]] = []

        def fake_run(command: list[str]) -> str:
            commands.append(tuple(command))
            if command[:3] == ["docker", "network", "inspect"]:
                return json.dumps([{
                    "Driver": "bridge",
                    "EnableIPv6": False,
                    "Options": {"com.docker.network.bridge.name": "nh-egress0"},
                }])
            if command[:3] == ["nft", "list", "tables"]:
                raise checker.EgressCheckError("host inspection command failed")
            raise AssertionError(f"unexpected command: {command!r}")

        class FakePath:
            def __init__(self, _value: str) -> None:
                pass

            def iterdir(self):
                return [type("Interface", (), {"name": "nh-egress0"})()]

        with mock.patch.object(checker, "_run", side_effect=fake_run), mock.patch.object(
            checker, "Path", FakePath,
        ):
            with self.assertRaises(checker.EgressCheckError):
                checker.inspect_live_state(bundle)
        self.assertNotIn(("iptables-save",), commands)

    def test_checker_detects_backend_bridge_and_rule_drift(self) -> None:
        vault, policy = fixture()
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        state = observed_state(bundle)
        state["backend"] = "nftables"
        state["network_bridge"] = "br-changing"
        state["bridge_names"] = ["br-changing"]
        state["network_ipv6_enabled"] = True
        errors = checker.check(bundle, state)
        for expected in (
            "backend_mismatch", "network_bridge_mismatch", "bridge_missing",
            "network_ipv6_mismatch",
        ):
            self.assertIn(expected, errors)

    def test_checker_rejects_missing_or_ambiguous_ipv6_state(self) -> None:
        vault, policy = fixture()
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        missing = observed_state(bundle)
        del missing["network_ipv6_enabled"]
        with self.assertRaises(checker.EgressCheckError):
            checker.check(bundle, missing)
        ambiguous = observed_state(bundle)
        ambiguous["network_ipv6_enabled"] = None
        with self.assertRaises(checker.EgressCheckError):
            checker.check(bundle, ambiguous)

    def test_checker_rejects_bundle_claiming_enabled_ipv6(self) -> None:
        vault, policy = fixture()
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        bundle["manifest"]["network_ipv6_enabled"] = True
        digest = generator.manifest_digest(bundle["manifest"])
        bundle["manifest_sha256"] = digest
        bundle["ruleset"] = generator.build_ruleset(bundle["manifest"], digest)
        with self.assertRaises(checker.EgressCheckError):
            checker.validate_bundle(bundle)

    def test_checker_rejects_an_unapplied_ipv6_ruleset_claim(self) -> None:
        vault, policy = fixture()
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        bundle["ruleset"]["ipv6"] = {
            "jump_rule": bundle["ruleset"]["ipv4"]["jump_rule"],
            "chain_rules": [f"-A {generator.CHAIN_NAME} -j DROP"],
        }
        with self.assertRaises(checker.EgressCheckError):
            checker.validate_bundle(bundle)

    def test_checker_requires_jump_to_be_first(self) -> None:
        vault, policy = fixture()
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        state = observed_state(bundle)
        state["ipv4_save"] = state["ipv4_save"].replace(
            "-A FORWARD -j DOCKER-USER\n",
            "-A FORWARD -j DOCKER-USER\n-A DOCKER-USER -i nh-egress0 -j ACCEPT\n",
        )
        self.assertIn("ipv4_jump_missing_or_not_first", checker.check(bundle, state))

    def test_checker_rejects_near_name_or_comment_only_forward_jump(self) -> None:
        vault, policy = fixture()
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        replacements = (
            "-A FORWARD -j DOCKER-USER-ALT",
            '-A FORWARD -m comment --comment "-j DOCKER-USER" -j ACCEPT',
        )
        for replacement in replacements:
            with self.subTest(rule=replacement):
                state = observed_state(bundle)
                state["ipv4_save"] = state["ipv4_save"].replace(
                    "-A FORWARD -j DOCKER-USER", replacement,
                )
                self.assertIn(
                    "ipv4_docker_user_unreachable", checker.check(bundle, state),
                )

    def test_checker_rejects_tampered_manifest_digest(self) -> None:
        vault, policy = fixture()
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        bundle["manifest"]["dns_resolvers"] = []
        with self.assertRaises(checker.EgressCheckError):
            checker.validate_bundle(bundle)

    def test_checker_rejects_port_range_overlap_even_with_recomputed_digest(self) -> None:
        vault, policy = fixture()
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        scope = next(
            item for item in bundle["manifest"]["targets"]
            if "192.0.2.10" in item["destinations"]
        )
        scope["tcp_port_ranges"] = [[20, 30]]
        digest = generator.manifest_digest(bundle["manifest"])
        bundle["manifest_sha256"] = digest
        bundle["ruleset"] = generator.build_ruleset(bundle["manifest"], digest)
        with self.assertRaises(checker.EgressCheckError):
            checker.validate_bundle(bundle)

    def test_checker_rejects_lan_target_outside_scope_with_recomputed_contract(self) -> None:
        vault, policy = fixture("lan-constrained")
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        outside_address = str(RFC1918_TEST_BLOCKS[1].network_address + 1)
        bundle["manifest"]["targets"][0]["destinations"] = [outside_address]
        digest = generator.manifest_digest(bundle["manifest"])
        bundle["manifest_sha256"] = digest
        bundle["ruleset"] = generator.build_ruleset(bundle["manifest"], digest)
        with self.assertRaisesRegex(
            checker.EgressCheckError,
            "target is outside the declared LAN scope",
        ):
            checker.validate_bundle(bundle)

    def test_checker_rejects_alias_even_with_recomputed_digest(self) -> None:
        vault, policy = fixture()
        bundle = generator.build_bundle(vault, policy, "netops-runner")
        bundle["manifest"]["targets"][0]["alias"] = "device-alpha"
        digest = generator.manifest_digest(bundle["manifest"])
        bundle["manifest_sha256"] = digest
        bundle["ruleset"] = generator.build_ruleset(bundle["manifest"], digest)
        with self.assertRaises(checker.EgressCheckError):
            checker.validate_bundle(bundle)


if __name__ == "__main__":
    unittest.main()
