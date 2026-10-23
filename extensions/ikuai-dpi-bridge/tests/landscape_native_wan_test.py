"""Native SQLite metadata, multi-WAN refresh, and stale-policy regressions."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("native_control_test", ROOT / "adapters/landscape/web_control.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class NativeWanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / "landscape.sqlite"
        self.conn = sqlite3.connect(self.db)
        self.addCleanup(self.conn.close)
        self.conn.executescript("""CREATE TABLE wan_links (
            id TEXT PRIMARY KEY, name TEXT, attach_iface_name TEXT, link_chain_id INTEGER,
            kind TEXT, v4 TEXT, nat TEXT);
            CREATE TABLE flow_configs (flow_id INTEGER, enable INTEGER,
                packet_handle_iface_name TEXT);""")
        self.ids = []

    def wan(self, name, iface, flow=None, kind=None):
        ident = str(uuid.uuid4())
        self.ids.append(ident)
        self.conn.execute("INSERT INTO wan_links VALUES (?,?,?,?,?,?,?)",
            (ident, name, iface, len(self.ids), json.dumps(kind or {"t": "ethernet"}),
             '{"enable":true}', '{"enable":true}'))
        if flow is not None:
            self.flow(flow, [ident])
        self.conn.commit()
        return ident

    def flow(self, number, targets):
        self.conn.execute("INSERT INTO flow_configs VALUES (?,1,?)", (number,
            json.dumps([{"target": {"t": "interface", "link_id": x, "name": "unused"}, "weight": 1} for x in targets])))

    def control(self):
        (self.root / "catalog.json").write_text(json.dumps({"entries": [
            {"entry_kind": "application_id", "app_id": str(i), "application": "App " + str(i)} for i in (1, 2, 3)]}))
        (self.root / "token").write_text("x" * 40)
        (self.root / "token").chmod(0o600)
        value = {"schema_version": 1, "mode": "preview", "state_dir": str(self.root / "state"),
            "token_file": str(self.root / "token"), "catalog": str(self.root / "catalog.json"),
            "clients": ["192.0.2.69"], "landscape_database": str(self.db)}
        path = self.root / "control.json"
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return m.Control(m.load_config(path))

    def save(self, c, ident):
        return c.save({"expected_revision": c.record["revision"], "rules": [
            {"appid": 1, "line_id": ident, "learn_endpoint": True, "allow_udp_endpoint_hints": False}]})

    def test_zero_one_and_three_wans_without_default_carrier_names(self):
        c = self.control()
        self.assertEqual(c.status()["lines"], [])
        self.wan("光纤 A", "eth1", 3)
        self.assertEqual(len(c.status()["lines"]), 1)
        self.wan("企业出口", "eth2", 9)
        third = self.wan("5G 备用", "wwan0", 12)
        lines = c.status()["lines"]
        self.assertEqual([x["name"] for x in lines], ["光纤 A", "企业出口", "5G 备用"])
        self.save(c, third)
        self.assertEqual(c.policy()["applications"]["1"]["flow_id"], 12)
        self.assertEqual(c.status()["wan_source"], "landscape")

    def test_rename_keeps_id_and_saved_policy_but_delete_blocks_apply_and_restarts_cleanly(self):
        ident = self.wan("原名称", "eth1", 7)
        c = self.control()
        self.save(c, ident)
        self.conn.execute("UPDATE wan_links SET name=? WHERE id=?", ("改名后的出口", ident))
        self.conn.commit()
        self.assertEqual(c.status()["lines"][0]["name"], "改名后的出口")
        self.assertEqual(c.record["rules"][0]["line_id"], ident)
        self.conn.execute("DELETE FROM wan_links WHERE id=?", (ident,))
        self.conn.commit()
        self.assertEqual(c.status()["lines"], [])
        with self.assertRaisesRegex(m.ControlError, "已不存在"):
            c.apply({"revision": 1, "initial_quiescent": True})
        reloaded = self.control()
        self.assertEqual(reloaded.record["rules"][0]["line_id"], ident)

    def test_read_only_live_wal_and_no_ppp_password_in_output(self):
        self.conn.execute("PRAGMA journal_mode=WAL")
        ident = self.wan("拨号", "eth1", 5, {"t": "pppd", "ppp_iface_name": "ppp7", "peer_id": "secret-user", "password": "never-export"})
        c = self.control()
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        status = c.status()
        self.assertEqual(status["lines"][0]["wan_ifname"], "ppp7")
        self.assertNotIn("never-export", json.dumps(status))
        self.assertNotIn("secret-user", json.dumps(status))
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), before)
        self.conn.execute("UPDATE wan_links SET name='WAL 新名称' WHERE id=?", (ident,))
        self.conn.commit()
        self.assertEqual(c.status()["lines"][0]["name"], "WAL 新名称")

    def test_weighted_multiple_wan_flow_is_not_reported_as_dedicated_exit(self):
        first = self.wan("主线", "eth1")
        second = self.wan("备线", "eth2")
        self.flow(3, [first, second])
        self.flow(9, [second])
        self.conn.commit()
        lines = self.control().status()["lines"]
        self.assertIsNone(lines[0]["flow_id"])
        self.assertFalse(lines[0]["configured_ready"])
        self.assertEqual(lines[1]["flow_id"], 9)

    def test_source_failure_is_unavailable_never_falls_back_to_old_lines(self):
        ident = self.wan("线路", "eth1", 3)
        c = self.control()
        self.save(c, ident)
        self.conn.execute("ALTER TABLE wan_links RENAME TO unavailable_wans")
        self.conn.commit()
        status = c.status()
        self.assertEqual(status["state"], "unavailable")
        self.assertEqual(status["lines"], [])
        with self.assertRaisesRegex(m.ControlError, "无法读取"):
            c.apply({"revision": 1, "initial_quiescent": True})

    def test_removed_active_wan_stops_producer_but_rename_does_not(self):
        ident = self.wan("线路", "eth1", 3)
        c = self.control()
        self.save(c, ident)
        runtime = unittest.mock.Mock()
        runtime.alive.return_value = True
        runtime.inspect.return_value = {"runtime": {"admission_live": False}}
        c.runtime, c.mode, c.live_revision = runtime, "live", 1
        self.conn.execute("UPDATE wan_links SET name='新名称'")
        self.conn.commit()
        c.refresh_lines()
        runtime.stop.assert_not_called()
        self.conn.execute("DELETE FROM wan_links")
        self.conn.commit()
        runtime.stop.side_effect = lambda **kw: setattr(runtime.alive, 'return_value', False)
        c.refresh_lines()
        runtime.stop.assert_called_once()
        self.assertIsNone(c.live_revision)
        self.assertFalse(c.runtime_unverified)

    def test_missing_database_is_not_created(self):
        c = self.control()
        c.config["landscape_database"] = str(self.root / "missing.sqlite")
        self.assertEqual(c.status()["state"], "unavailable")
        self.assertFalse((self.root / "missing.sqlite").exists())

    def test_failed_wan_revocation_is_retried_until_admission_is_confirmed_closed(self):
        ident = self.wan("线路", "eth1", 3)
        c = self.control()
        self.save(c, ident)
        runtime = unittest.mock.Mock()
        runtime.alive.return_value = True
        runtime.stop.side_effect = RuntimeError('temporary stop failure')
        c.runtime, c.mode, c.live_revision = runtime, "live", 1
        self.conn.execute("DELETE FROM wan_links")
        self.conn.commit()
        c.refresh_lines()
        self.assertTrue(c.runtime_unverified)
        self.assertTrue(c.wan_revocation_pending)
        runtime.stop.side_effect = lambda **kw: setattr(runtime.alive, 'return_value', False)
        runtime.inspect.return_value = {"runtime": {"admission_live": False}}
        c.refresh_lines()
        self.assertFalse(c.runtime_unverified)
        self.assertFalse(c.wan_revocation_pending)


if __name__ == "__main__":
    unittest.main()
