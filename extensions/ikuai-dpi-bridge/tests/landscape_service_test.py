import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest

BASE = Path(__file__).resolve().parents[1] / "adapters/landscape"
spec = importlib.util.spec_from_file_location("landscape_service", BASE / "service_runner.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class Child:
    def __init__(self, result=None, hang=False):
        self.stdout = io.BytesIO(); self.result = result; self.hang = hang; self.actions = []
    def poll(self): return self.result
    def terminate(self): self.actions.append("terminate"); self.result = -15
    def kill(self): self.actions.append("kill"); self.hang = False; self.result = -9
    def wait(self, timeout):
        self.actions.append("wait")
        if self.hang: raise subprocess.TimeoutExpired("fixture", timeout)
        self.result = self.result or 0
        return self.result


class LandscapeServiceTests(unittest.TestCase):
    def test_full_catalog_and_exact_client_capture_no_cooked_device(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder); (p / "rules").write_text("{}")
            (p / "policy").write_text(json.dumps({"schema_version": 1, "clients": ["10.10.10.69"], "applications": {}}))
            args = types.SimpleNamespace(policy=p / "policy", rules=p / "rules", binary=sys.executable,
                    interface="br-lan", pin_root="/sys/fs/bpf/landscape/test", initialize_quiescent=True, resume=False, max_flows=4096)
            plan = m.commands(args)
            self.assertIn("--quiet", plan[2]); self.assertIn("--all", plan[1]); self.assertNotIn("--appids", plan[1])
            self.assertEqual(plan[0][-1], "(tcp or udp) and (host 10.10.10.69)")
            self.assertIn("10.10.10.69/32", plan[1]); self.assertIn("--initialize-quiescent", plan[2])
            args.interface = "any"
            with self.assertRaises(ValueError): m.commands(args)

    def test_stop_propagates_eof_and_does_not_reset_maps(self):
        children = [Child(), Child(), Child()]; calls = []
        def popen(command, **kwargs):
            calls.append(command); return children[len(calls)-1]
        self.assertEqual(m.supervise([["capture"], ["classify"], ["receive"]], lambda: True, popen), 0)
        self.assertTrue(children[0].stdout.closed); self.assertTrue(children[1].stdout.closed)
        self.assertEqual(children[0].actions, ["terminate", "wait"])
        self.assertEqual(children[2].actions, ["wait"])
        self.assertEqual(len(calls), 3)

    def test_live_component_eof_is_failure_and_stops_upstream(self):
        children = [Child(), Child(), Child(result=0)]; pool = iter(children)
        self.assertEqual(m.supervise([[], [], []], lambda: False, lambda *a, **k: next(pool)), 2)
        self.assertIn("terminate", children[0].actions)

    def test_partial_spawn_failure_cleans_up_existing_process(self):
        capture = Child(); count = 0
        def popen(*a, **kw):
            nonlocal count
            count += 1
            if count > 1: raise OSError("fixture cannot launch classifier")
            return capture
        with self.assertRaises(OSError): m.supervise([[], [], []], lambda: False, popen)
        self.assertTrue(capture.stdout.closed); self.assertIn("terminate", capture.actions)

    def test_hung_downstream_is_bounded_and_killed(self):
        children = [Child(), Child(hang=True), Child()]; pool = iter(children)
        self.assertEqual(m.supervise([[], [], []], lambda: True, lambda *a, **k: next(pool)), 0)
        self.assertIn("kill", children[1].actions)

    def test_unreapable_child_does_not_skip_receiver_cleanup(self):
        class Unreapable(Child):
            def kill(self): self.actions.append("kill")
        children = [Unreapable(hang=True), Child(hang=True), Child(hang=True)]
        pool = iter(children)
        with self.assertRaises(RuntimeError):
            m.supervise([[], [], []], lambda: True, lambda *a, **k: next(pool))
        self.assertTrue(all("kill" in child.actions for child in children))


if __name__ == "__main__": unittest.main()
