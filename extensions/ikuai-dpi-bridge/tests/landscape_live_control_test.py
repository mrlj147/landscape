"""Configured deployment boundaries; synthetic fixtures, no kernel/network writes."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from landscape_web_control_test import m, FakeRuntime


def deployment(folder):
    root = Path(folder)
    catalog = {"entries": [{"entry_kind": "application_id", "app_id": "42", "application": "Example app", "translations": ["示例应用"]}]}
    rules = {"synthetic": True}
    (root / "catalog.json").write_text(json.dumps(catalog))
    (root / "rules.json").write_text(json.dumps(rules))
    sources = {name: {"bytes": (root / filename).stat().st_size, "sha256": hashlib.sha256((root / filename).read_bytes()).hexdigest()} for name, filename in (("catalog.json", "catalog.json"), ("all-rules.json", "rules.json"))}
    mapping = {"metadata": {"source_files": sources}, "applications": [{"app_id": "42", "category_path": ["网络应用", "示例分类"], "rule_count": 50, "domains": [f"app{i}.example.test" for i in range(30)], "ips": ["192.0.2.1"], "cidrs": [], "domain_patterns": []}]}
    (root / "applications.json").write_text(json.dumps(mapping))
    (root / "token").write_text("synthetic_control_token_with_32_characters")
    (root / "token").chmod(0o600)
    value = {"schema_version": 1, "mode": "live", "state_dir": str(root / "state"), "token_file": str(root / "token"), "catalog": str(root / "catalog.json"), "application_map": str(root / "applications.json"), "rules": str(root / "rules.json"), "binary": sys.executable, "clients": ["192.0.2.69"], "interface": "br-lan", "pin_root": "/sys/fs/bpf/landscape/default", "lines": [{"id": "telecom", "name": "电信", "flow_id": 1, "wan_ifname": "ppp0"}, {"id": "unicom", "name": "联通", "flow_id": 2, "wan_ifname": "ppp1"}]}
    # Copy an executable fixture owned by this test user, never a submitted shell command.
    import shutil
    shutil.copyfile(sys.executable, root / "classifier")
    (root / "classifier").chmod(0o700)
    value["binary"] = str(root / "classifier")
    path = root / "control.json"
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path, value


class LiveControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path, self.value = deployment(self.tmp.name)

    def write(self, **changes):
        self.path.write_text(json.dumps(dict(self.value, **changes)))
        return m.load_config(self.path)

    def test_live_config_is_explicit_and_never_selects_a_network_namespace(self):
        cfg = m.load_config(self.path)
        self.assertEqual(m.namespace_prefix(cfg), [])
        for changes in ({"netns": "other"}, {"interface": "ppp0"}, {"interface": "any"}, {"interface": "eth0;reboot"}, {"pin_root": "/sys/fs/bpf/unrelated"}, {"pin_root": "/sys/fs/bpf/landscape/../unrelated"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.write(**changes)

    def test_mixed_library_versions_are_refused_before_runtime_creation(self):
        Path(self.value["rules"]).write_text('{"changed":true}')
        with patch.object(m, "ProcessRuntime", side_effect=AssertionError("no runtime")):
            with self.assertRaisesRegex(ValueError, "versions do not match"):
                m.load_config(self.path)

    def test_category_domain_ip_search_and_bounded_metadata_are_returned(self):
        control = m.Control(m.load_config(self.path), FakeRuntime())
        for term in ("示例分类", "app29.example.test", "192.0.2.1", "42", "Example"):
            item = control.search(term)["items"][0]
            self.assertEqual(item["category_path"], ["网络应用", "示例分类"])
            self.assertEqual(len(item["domains"]), 16)
            self.assertEqual(item["endpoint_counts"]["domains"], 30)
            self.assertNotIn("_search", item)

    def test_incomplete_application_map_is_refused(self):
        Path(self.value["application_map"]).write_text(json.dumps({"applications": []}))
        with self.assertRaisesRegex(ValueError, "complete catalog"):
            m.load_catalog(self.value["catalog"], self.value["application_map"])

    def test_live_save_apply_stop_checks_real_runtime_and_keeps_sticky_connections(self):
        runtime = FakeRuntime()
        control = m.Control(m.load_config(self.path), runtime)
        control.save({"expected_revision": 0, "rules": [{"appid": 42, "line_id": "unicom", "learn_endpoint": True, "allow_udp_endpoint_hints": False}]})
        with self.assertRaises(m.ControlError) as got:
            control.apply({"revision": 1, "initial_quiescent": False})
        self.assertEqual(got.exception.error_id, "quiescence_required")
        active = control.apply({"revision": 1, "initial_quiescent": True})
        self.assertEqual(active["active_revision"], 1)
        self.assertEqual(runtime.policy["applications"]["42"]["wan_ifname"], "ppp1")
        stopped = control.stop({})
        self.assertIsNone(stopped["active_revision"])
        self.assertEqual(stopped["runtime"]["pinned_connections"][0]["nat_session_token"], 123)
        restarted = m.Control(m.load_config(self.path), FakeRuntime()).status()
        self.assertIsNone(restarted["active_revision"])
        self.assertEqual(restarted["last_applied_revision"], 1)

    def test_live_on_mac_cannot_run_external_processes(self):
        with patch.object(m.sys, "platform", "darwin"), patch.object(m.subprocess, "run", side_effect=AssertionError):
            with self.assertRaises(ValueError):
                m.ProcessRuntime(m.load_config(self.path))

    def test_live_lan_requires_the_exact_attached_map_ids(self):
        class Backend:
            wrong = False
            def command(self, kind, verb, *args):
                if kind == "map":
                    return {"id": {"dpi_rt_cfg_v1": 1, "dpi_rt_cli_v1": 2, "dpi_rt_flow_v1": 3, "dpi_rt_hint_v1": 4}[Path(args[-1]).name]}
                return [{"map_ids": [1, 2, 3, 99] if self.wrong else [1, 2, 3, 4]}]
        backend = Backend()
        result = types.SimpleNamespace(stdout=json.dumps([{"kind": "bpf", "options": {"id": 9}}]))
        with patch.object(m.subprocess, "run", return_value=result) as run:
            m.validate_lan_program(self.value, backend)
            self.assertEqual(run.call_args.args[0][-2:], ["br-lan", "ingress"])
            backend.wrong = True
            with self.assertRaisesRegex(ValueError, "no attached"):
                m.validate_lan_program(self.value, backend)

if __name__ == "__main__":
    unittest.main()
