"""Offline packaging safety: validation, hashes, permissions, no service execution."""
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
from landscape_live_control_test import deployment

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("stage_install", ROOT / "deployment/stage_install.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        _, self.config = deployment(self.root)
        (self.root / "all-rules.json").write_bytes((self.root / "rules.json").read_bytes())
        elf = bytearray(64); elf[:6] = b"\x7fELF\x02\x01"; elf[18:20] = (62).to_bytes(2, "little")
        (self.root / "linux-binary").write_bytes(elf)
        self.args = types.SimpleNamespace(output=self.root / "install", library=self.root, binary=self.root / "linux-binary", client=["192.0.2.69"], lan="br-lan", pin_root="/sys/fs/bpf/landscape/default", telecom_flow=1, telecom_wan="ppp0", unicom_flow=2, unicom_wan="ppp1")

    def test_offline_package_validates_private_same_version_files_and_starts_nothing(self):
        with patch.object(m.m.subprocess, "run", side_effect=AssertionError("network/service command forbidden")), patch.object(m.m.subprocess, "Popen", side_effect=AssertionError("spawn forbidden")):
            result = m.stage(self.args)
        self.assertFalse(result["services_started"]); self.assertFalse(result["network_modified"])
        cfg = self.args.output / "etc/landscape-dpi/control.json"
        self.assertEqual(cfg.stat().st_mode & 0o777, 0o600)
        value = json.loads(cfg.read_text())
        self.assertEqual(value["binary"], "/opt/landscape-dpi/bin/dpi-bridge")
        token = self.args.output / "var/lib/landscape-dpi/control.token"
        self.assertGreater(len(token.read_text().strip()), 32)
        self.assertEqual(token.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(token.read_text().strip(), json.dumps(result))
        with self.assertRaisesRegex(ValueError, "already exists"):
            m.stage(self.args)

    def test_mixed_library_rejected_before_output_creation(self):
        (self.root / "all-rules.json").write_text("{\"changed\":true}")
        with self.assertRaisesRegex(ValueError, "not the same version"):
            m.stage(self.args)
        self.assertFalse(self.args.output.exists())

    def test_macos_binary_and_ambiguous_lan_are_refused(self):
        self.args.binary.write_bytes(b"\xcf\xfa\xed\xfe" + bytes(60))
        with self.assertRaisesRegex(ValueError, "ELF"):
            m.stage(self.args)
        self.assertFalse(self.args.output.exists())
        self.args.lan = "ppp0"
        with self.assertRaisesRegex(ValueError, "distinct"):
            m.stage(self.args)
