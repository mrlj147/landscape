import copy
import http.client
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("landscape_web_control", ROOT / "adapters/landscape/web_control.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
_fixture_dir = tempfile.TemporaryDirectory()
_fixture = Path(_fixture_dir.name)
CATALOG = _fixture / "catalog.json"
CATALOG.write_text(json.dumps({"entries": [{"entry_kind": "application_id", "app_id": str(i), "application": "Synthetic app " + str(i), "translations": []} for i in list(range(1, 3307)) + [2550017,1540005,1540009,1000016]]}))
(_fixture / "rules.json").write_text("{}")
CURRENT = {"rules": str(_fixture / "rules.json")}
TOKEN = "offline_private_control_token_1234567890"


def rule(appid=2550017, line="telecom", learn=True, udp=False):
    return {"appid": appid, "line_id": line, "learn_endpoint": learn, "allow_udp_endpoint_hints": udp}


def config(folder, mode="preview"):
    root = Path(folder)
    token = root / "token"
    token.write_text(TOKEN)
    token.chmod(0o600)
    value = {"schema_version": 1, "mode": mode, "state_dir": str(root / "state"),
        "token_file": str(token), "catalog": str(CATALOG), "clients": ["10.10.10.69"],
        "lines": [{"id": "telecom", "name": "电信", "flow_id": 1, "wan_ifname": "wan1"},
                  {"id": "unicom", "name": "联通", "flow_id": 2, "wan_ifname": "wan2"}]}
    if mode == "lab":
        value.update(netns="dpi-web-lab", interface="lan0", pin_root="/sys/fs/bpf/landscape/dpi-web-lab/lan_maps",
                     rules=str(ROOT / CURRENT["rules"]), binary="/opt/dpi-bridge", max_flows=4096)
    path = root / "config.json"
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


class FakeRuntime:
    def __init__(self):
        self.running = False
        self.raw = {"armed": False, "admission_live": False, "pinned_connections": [{"flow_id": 1, "nat_session_token": 123}]}
        self.calls = []
        self.fail_preflight = self.fail_ready = self.unavailable = False
        self.unready = set()

    def alive(self):
        return self.running

    def inspect(self, force=False, policy=None, deadline=None):
        m.time_limit(deadline, 20)
        self.calls.append(("inspect", force, policy is not None))
        if self.unavailable or (policy is not None and self.fail_preflight):
            raise RuntimeError("fixture preflight rejected")
        return {"runtime": copy.deepcopy(self.raw), "lines": [
            {"id": line, "ready": line not in self.unready, "reason": "fixture readiness"}
            for line in ("telecom", "unicom")]}

    def start(self, policy, initialize, deadline=None):
        m.time_limit(deadline, 1)
        self.calls.append(("start", initialize))
        self.policy = json.loads(Path(policy).read_text())
        self.running = True
        self.raw["armed"] = True

    def wait_ready(self, deadline=None):
        m.time_limit(deadline, 20)
        self.calls.append(("wait_ready",))
        if self.fail_ready:
            raise RuntimeError("fixture start failed")
        self.raw["admission_live"] = True
        return self.inspect(force=True)

    def stop(self, deadline=None):
        m.time_limit(deadline, 1)
        self.calls.append(("stop",))
        self.running = False
        self.raw["admission_live"] = False


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def control(self, mode="preview"):
        self.cfg = m.load_config(config(self.tmp.name, mode))
        self.runtime = FakeRuntime() if mode == "lab" else None
        self.c = m.Control(self.cfg, self.runtime)
        return self.c

    def save(self, rules=None, expected=None):
        return self.c.save({"expected_revision": self.c.record["revision"] if expected is None else expected,
                            "rules": rules if rules is not None else [rule()]})

    def apply(self, initial=True, revision=None):
        return self.c.apply({"revision": self.c.record["revision"] if revision is None else revision,
                             "initial_quiescent": initial})

    def test_catalog_capacity_and_pagination_are_not_a_demo_whitelist(self):
        c = self.control()
        self.assertGreaterEqual(len(c.catalog), 3306)
        for appid in (2550017, 1540005, 1540009, 1000016):
            self.assertEqual(c.search(str(appid))["items"][0]["appid"], appid)
        first = c.search("", 0, 100)
        second = c.search("", 100, 100)
        self.assertEqual(first["total"], len(c.catalog))
        self.assertEqual(len(first["items"]), 100)
        self.assertTrue({x["appid"] for x in first["items"]}.isdisjoint(x["appid"] for x in second["items"]))

    def test_preview_never_constructs_or_calls_a_system_runtime(self):
        with patch.object(m, "ProcessRuntime", side_effect=AssertionError("must not initialize live runtime")), \
             patch.object(m.subprocess, "run", side_effect=AssertionError("offline execution forbidden")), \
             patch.object(m.subprocess, "Popen", side_effect=AssertionError("offline process forbidden")):
            c = self.control()
            saved = self.save()
            self.assertIsNone(saved["active_revision"])
            applied = self.apply(initial=False)
            self.assertEqual(applied["simulated_revision"], 1)
            self.assertIsNone(applied["active_revision"])
            self.assertIsNone(applied["runtime"])
            self.assertTrue(applied["simulated"])
            self.assertTrue(all(not x["ready"] for x in applied["lines"]))
            c.stop({})
            c.close()

    def test_preview_saved_and_simulated_revisions_are_distinct_and_persist(self):
        self.control()
        self.save()
        self.apply()
        self.save([rule(line="unicom")])
        current = m.Control(self.cfg).status()
        self.assertEqual((current["saved_revision"], current["simulated_revision"]), (2, 1))
        self.assertIsNone(current["active_revision"])
        self.assertIsNone(current["last_applied_revision"])
        self.c.stop({})
        self.assertIsNone(m.Control(self.cfg).status()["simulated_revision"])

    def test_save_rejects_unknown_apps_duplicates_commands_and_implicit_permissions(self):
        self.control()
        bad = [[rule(0xffffffff)], [rule(), rule()], [rule(line="wan1; reboot")],
               [rule(learn=1)], [rule(udp=True, learn=False)], [dict(rule(), client="1.1.1.1")],
               [rule(appid=True)], [rule(line={"cmd": "anything"})]]
        for rules in bad:
            with self.subTest(rules=rules), self.assertRaises(m.ControlError):
                self.save(rules)
        self.assertEqual(self.c.record["revision"], 0)
        with self.assertRaises(m.ControlError):
            self.c.save({"expected_revision": 0, "rules": [], "clients": ["10.10.10.1"]})

    def test_concurrent_save_has_one_winner_and_one_revision_conflict(self):
        self.control()
        results = []
        barrier = threading.Barrier(3)
        def save(line):
            barrier.wait()
            try:
                self.save([rule(line=line)], expected=0)
                results.append(200)
            except m.ControlError as exc:
                results.append(exc.status)
        threads = [threading.Thread(target=save, args=(line,)) for line in ("telecom", "unicom")]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(results), [200, 409])
        self.assertEqual(m.Control(self.cfg).record["revision"], 1)

    def test_failed_file_write_does_not_change_memory_or_existing_state(self):
        self.control()
        self.save()
        before = self.c.state_path.read_bytes()
        with patch.object(m, "atomic_json", side_effect=OSError("disk full")), self.assertRaises(OSError):
            self.save([rule(line="unicom")])
        self.assertEqual(self.c.record["revision"], 1)
        self.assertEqual(self.c.state_path.read_bytes(), before)

    def test_lab_initial_apply_requires_quiescence_and_real_ready_signal(self):
        self.control("lab")
        self.save()
        with self.assertRaises(m.ControlError) as got:
            self.apply(initial=False)
        self.assertEqual(got.exception.error_id, "quiescence_required")
        self.assertNotIn(("stop",), self.runtime.calls)
        state = self.apply()
        self.assertEqual(state["active_revision"], 1)
        self.assertFalse(state["simulated"])
        self.assertIn(("start", True), self.runtime.calls)
        self.assertEqual(self.runtime.policy["applications"]["2550017"]["wan_ifname"], "wan1")

    def test_lab_saved_changes_dont_change_active_revision_and_apply_resumes(self):
        self.control("lab")
        self.save()
        self.apply()
        state = self.save([rule(line="unicom")])
        self.assertEqual((state["saved_revision"], state["active_revision"]), (2, 1))
        self.apply(initial=False)
        self.assertIn(("start", False), self.runtime.calls)
        self.assertEqual(self.runtime.policy["applications"]["2550017"]["wan_ifname"], "wan2")
        self.assertEqual(self.c.status()["active_revision"], 2)
        self.assertEqual(self.runtime.raw["pinned_connections"][0]["nat_session_token"], 123)

    def test_preflight_failure_keeps_old_producer_and_active_policy(self):
        self.control("lab")
        self.save()
        self.apply()
        self.save([rule(line="unicom")])
        stop_count = self.runtime.calls.count(("stop",))
        self.runtime.fail_preflight = True
        with self.assertRaises(m.ControlError) as got:
            self.apply()
        self.assertEqual(got.exception.error_id, "preflight_failed")
        self.assertEqual(self.runtime.calls.count(("stop",)), stop_count)
        self.assertEqual(self.c.status()["active_revision"], 1)

    def test_unready_selected_line_rejected_before_stopping_previous_policy(self):
        self.control("lab")
        self.save()
        self.apply()
        self.save([rule(line="unicom")])
        self.runtime.unready.add("unicom")
        with self.assertRaises(m.ControlError) as got:
            self.apply()
        self.assertEqual(got.exception.error_id, "line_unavailable")
        self.assertEqual(self.c.status()["active_revision"], 1)

    def test_failed_apply_never_claims_new_revision_active_or_erases_old_connections(self):
        self.control("lab")
        self.save()
        self.apply()
        self.save([rule(line="unicom")])
        self.runtime.fail_ready = True
        with self.assertRaises(m.ControlError) as got:
            self.apply()
        self.assertEqual(got.exception.error_id, "apply_failed")
        state = self.c.status()
        self.assertEqual(state["state"], "error")
        self.assertIsNone(state["active_revision"])
        self.assertEqual(state["last_applied_revision"], 1)
        self.assertEqual(state["runtime"]["pinned_connections"][0]["nat_session_token"], 123)
        self.assertFalse(self.runtime.alive())

    def test_stop_drains_new_admission_and_retains_pinned_connections(self):
        self.control("lab")
        self.save()
        self.apply()
        state = self.c.stop({})
        self.assertIsNone(state["active_revision"])
        self.assertTrue(state["runtime"]["armed"])
        self.assertFalse(state["runtime"]["admission_live"])
        self.assertEqual(state["runtime"]["pinned_connections"][0]["nat_session_token"], 123)

    def test_foreign_live_producer_cannot_be_overwritten_or_stopped(self):
        self.control("lab")
        self.save()
        self.runtime.raw.update(armed=True, admission_live=True)
        for action in (lambda: self.apply(), lambda: self.c.stop({})):
            with self.assertRaises(m.ControlError) as got:
                action()
            self.assertEqual(got.exception.error_id, "producer_conflict")
        self.assertNotIn(("stop",), self.runtime.calls)
        self.assertEqual(self.c.status()["state"], "unavailable")

    def test_stale_apply_cannot_touch_the_runtime(self):
        self.control("lab")
        self.save()
        calls = len(self.runtime.calls)
        with self.assertRaises(m.ControlError) as got:
            self.apply(revision=0)
        self.assertEqual(got.exception.status, 409)
        self.assertEqual(len(self.runtime.calls), calls)

    def test_runtime_disappearance_and_pipeline_exit_are_not_reported_running(self):
        self.control("lab")
        self.save()
        self.apply()
        self.runtime.running = False
        self.assertEqual(self.c.status()["state"], "error")
        self.assertIsNone(self.c.status()["active_revision"])
        self.runtime.unavailable = True
        self.assertEqual(self.c.status()["state"], "unavailable")

    def test_shutdown_refuses_late_mutations(self):
        self.control()
        self.c.close()
        for action in (lambda: self.save(), lambda: self.apply(), lambda: self.c.stop({})):
            with self.assertRaises(m.ControlError) as got:
                action()
            self.assertEqual(got.exception.error_id, "shutting_down")

    def test_apply_cumulative_work_budget_prevents_any_later_start(self):
        self.control("lab")
        self.save()
        clock = [100.0]
        old_inspect, old_stop = self.runtime.inspect, self.runtime.stop
        stops = []
        def inspect(force=False, policy=None, deadline=None):
            if policy is not None:
                clock[0] += 20
            return old_inspect(force, policy, deadline)
        def stop(deadline=None):
            stops.append(deadline)
            if len(stops) == 1:
                clock[0] += 50.1
            return old_stop(deadline)
        self.runtime.inspect, self.runtime.stop = inspect, stop
        with patch.object(m.time, "monotonic", side_effect=lambda: clock[0]):
            with self.assertRaises(m.ControlError) as got:
                self.apply()
        self.assertEqual(got.exception.error_id, "apply_failed")
        self.assertEqual(stops, [170.0, 185.0])
        self.assertFalse(any(call[0] == "start" for call in self.runtime.calls))
        self.assertIsNone(self.c.record["last_applied_revision"])
        self.assertLessEqual(clock[0], 185)

    def test_request_deadline_is_not_restarted_after_body_was_read(self):
        self.control("lab")
        self.save()
        seen = []
        old_inspect = self.runtime.inspect
        def inspect(force=False, policy=None, deadline=None):
            seen.append((policy is not None, deadline))
            return old_inspect(force, policy, deadline)
        self.runtime.inspect = inspect
        with patch.object(m.time, "monotonic", return_value=100):
            self.c.apply({"revision": 1, "initial_quiescent": True}, deadline=150)
        self.assertEqual(seen[0], (True, 135))  # 15 seconds reserved inside the existing deadline
        self.assertTrue(all(d <= 150 for _, d in seen if d is not None))

    def test_unverified_timeout_blocks_writes_until_explicit_stop_verifies_drain(self):
        self.control("lab")
        self.save()
        clock = [100.0]
        old_stop = self.runtime.stop
        stops = []
        def stop(deadline=None):
            stops.append(deadline)
            if len(stops) == 2:
                raise RuntimeError("fixture cannot verify process termination")
            return old_stop(deadline)
        def wait_ready(deadline=None):
            clock[0] += 70.1
            m.time_limit(deadline, 1)
        self.runtime.stop, self.runtime.wait_ready = stop, wait_ready
        with patch.object(m.time, "monotonic", side_effect=lambda: clock[0]):
            with self.assertRaises(m.ControlError) as got:
                self.apply()
            self.assertEqual(got.exception.error_id, "runtime_unverified")
            current = self.c.status()
            self.assertTrue(current["runtime_unverified"])
            self.assertIsNone(current["active_revision"])
            self.assertTrue(self.runtime.alive())  # response must not claim shutdown succeeded
            for action in (lambda: self.save(), lambda: self.apply()):
                with self.assertRaises(m.ControlError) as blocked:
                    action()
                self.assertEqual(blocked.exception.error_id, "runtime_unverified")
            self.runtime.stop = old_stop
            recovered = self.c.stop({})
            self.assertFalse(recovered["runtime_unverified"])
            self.assertEqual(recovered["state"], "stopped")
            self.save()

    def test_busy_apply_rejects_writes_instead_of_queuing_late_mutations(self):
        self.control("lab")
        self.save()
        entered, finish = threading.Event(), threading.Event()
        original = self.runtime.wait_ready
        def wait_ready(deadline=None):
            entered.set()
            finish.wait(timeout=2)
            return original(deadline)
        self.runtime.wait_ready = wait_ready
        outcomes = []
        def apply():
            try:
                outcomes.append(self.apply())
            except BaseException as exc:
                outcomes.append(exc)
        thread = threading.Thread(target=apply)
        thread.start()
        self.assertTrue(entered.wait(timeout=2))
        try:
            with self.assertRaises(m.ControlError) as got:
                self.save()
            self.assertEqual(got.exception.error_id, "operation_busy")
        finally:
            finish.set()
            thread.join(timeout=3)
        self.assertIsInstance(outcomes[0], dict)
        self.assertEqual(self.c.record["revision"], 1)

    def test_production_and_management_namespace_configs_are_rejected(self):
        path = config(self.tmp.name, "lab")
        value = json.loads(path.read_text())
        for changed in (dict(value, mode="production"), dict(value, netns="root"), dict(value, interface="eth0"),
                        dict(value, pin_root="/sys/fs/bpf/landscape/dpi-lab-web"), dict(value, clients=["10.10.10.1"])):
            path.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                m.load_config(path)

    def test_live_mode_fails_on_mac_before_any_external_command(self):
        with patch.object(m.sys, "platform", "darwin"), patch.object(m.subprocess, "run", side_effect=AssertionError):
            with self.assertRaises(ValueError):
                m.ProcessRuntime({})
            with self.assertRaises(ValueError):
                m.runtime_inspect({"mode": "preview"})

    def test_unsafe_files_or_state_directory_are_rejected(self):
        path = config(self.tmp.name)
        path.chmod(0o666)
        with self.assertRaises(ValueError):
            m.load_config(path)
        path.chmod(0o600)
        cfg = m.load_config(path)
        Path(cfg["state_dir"]).mkdir(mode=0o755)
        with self.assertRaises(ValueError):
            m.Control(cfg)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.control = m.Control(m.load_config(config(self.tmp.name)))
        self.server = m.Server(("127.0.0.1", 0), self.control, TOKEN)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.control.close()
        self.tmp.cleanup()

    def request(self, method="GET", path="/status", body=None, headers=None, auth=True):
        request_headers = {"Authorization": "Bearer " + TOKEN} if auth else {}
        request_headers.update(headers or {})
        if isinstance(body, dict):
            body = json.dumps(body)
            request_headers.setdefault("Content-Type", "application/json")
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            client.request(method, path, body, request_headers)
            response = client.getresponse()
            return response.status, json.loads(response.read())
        finally:
            client.close()

    def test_auth_loopback_origin_host_and_response_envelope(self):
        self.assertEqual(self.request(auth=False)[0], 401)
        self.assertEqual(self.request(headers={"Authorization": "Bearer wrong"})[0], 401)
        self.assertEqual(self.request(headers={"Origin": "https://attacker.example"})[0], 403)
        self.assertEqual(self.request(headers={"Origin": "null"})[0], 403)
        self.assertEqual(self.request(headers={"Host": "attacker.example"})[0], 403)
        code, result = self.request(headers={"Origin": "http://127.0.0.1:5173"})
        self.assertEqual(code, 200)
        self.assertEqual(result["data"]["mode"], "preview")
        self.assertNotIn(TOKEN, json.dumps(result))

    def test_strict_paths_query_pagination_and_methods(self):
        for path in ("/status/", "/%73tatus", "/unknown"):
            self.assertEqual(self.request(path=path)[0], 404)
        for path in ("/status?x=1", "/catalog?limit=101", "/catalog?offset=-1", "/catalog?q=a&q=b", "/catalog?bad=1"):
            self.assertEqual(self.request(path=path)[0], 400)
        code, result = self.request(path="/catalog?q=2550017&limit=20&offset=0")
        self.assertEqual(code, 200)
        self.assertEqual(result["data"]["items"][0]["appid"], 2550017)
        self.assertEqual(self.request("DELETE", "/policy")[0], 404)

    def test_body_limits_content_type_duplicate_keys_and_unexpected_fields(self):
        self.assertEqual(self.request("PUT", "/policy", "{}", {"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.request("POST", "/stop", "", {"Content-Length": str(m.MAX_BODY + 1), "Content-Type": "application/json"})[0], 413)
        self.assertEqual(self.request("POST", "/stop", '{"x":1,"x":2}', {"Content-Type": "application/json"})[0], 400)
        self.assertEqual(self.request("POST", "/stop", {"reset": True})[0], 400)
        self.assertEqual(self.request("PUT", "/policy", {"expected_revision": True, "rules": []})[0], 400)

    def test_http_save_apply_stop_and_revision_conflict(self):
        self.assertEqual(self.request("PUT", "/policy", {"expected_revision": 0, "rules": [rule()]})[0], 200)
        self.assertEqual(self.request("PUT", "/policy", {"expected_revision": 0, "rules": []})[0], 409)
        code, result = self.request("POST", "/apply", {"revision": 1, "initial_quiescent": False})
        self.assertEqual(code, 200)
        self.assertEqual(result["data"]["simulated_revision"], 1)
        self.assertIsNone(result["data"]["active_revision"])
        code, result = self.request("POST", "/stop", {})
        self.assertEqual(code, 200)
        self.assertEqual(result["data"]["state"], "stopped")


class RuntimeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = m.load_config(config(self.tmp.name, "lab"))
        Path(self.cfg["state_dir"]).mkdir(mode=0o700)

    def runtime(self):
        with patch.object(m.sys, "platform", "linux"), patch.object(m.os, "geteuid", return_value=0):
            return m.ProcessRuntime(self.cfg)

    def test_runtime_inspection_is_fixed_namespace_command_with_timeout_and_safe_env(self):
        runtime = self.runtime()
        output = {"runtime": {"armed": False, "admission_live": False, "pinned_connections": []}, "lines": []}
        completed = types.SimpleNamespace(returncode=0, stdout=json.dumps(output), stderr="")
        with patch.object(m.subprocess, "run", return_value=completed) as run:
            self.assertEqual(runtime.inspect(force=True), output)
            command = run.call_args.args[0]
            self.assertEqual(command[:4], ["/usr/sbin/ip", "netns", "exec", "dpi-web-lab"])
            self.assertIn("runtime", command)
            self.assertEqual(run.call_args.kwargs["timeout"], 20)
            self.assertEqual(run.call_args.kwargs["env"], m.SAFE_ENV)
            self.assertNotIn("shell", run.call_args.kwargs)
            runtime.inspect()
            self.assertEqual(run.call_count, 1)

    def test_inspection_caps_subprocess_timeout_at_remaining_request_budget(self):
        runtime = self.runtime()
        completed = types.SimpleNamespace(returncode=0, stdout='{"runtime":{},"lines":[]}', stderr="")
        with patch.object(m.time, "monotonic", return_value=100), patch.object(m.subprocess, "run", return_value=completed) as run:
            runtime.inspect(force=True, deadline=103)
            self.assertEqual(run.call_args.kwargs["timeout"], 3)

    def test_expired_deadline_cannot_spawn_or_inspect_any_process(self):
        runtime = self.runtime()
        with patch.object(m.time, "monotonic", return_value=100), \
             patch.object(m.subprocess, "run", side_effect=AssertionError("late inspect forbidden")), \
             patch.object(m.subprocess, "Popen", side_effect=AssertionError("late start forbidden")):
            with self.assertRaises(m.OperationDeadline):
                runtime.inspect(deadline=99)
            with self.assertRaises(m.OperationDeadline):
                runtime.start(Path(self.tmp.name) / "policy.json", True, deadline=99)

    def test_wait_ready_does_not_add_another_twenty_second_probe_after_deadline(self):
        runtime = self.runtime()
        clock, calls = [100.0], []
        runtime.process = types.SimpleNamespace(poll=lambda: None)
        def inspect(force=False, policy=None, deadline=None):
            calls.append(deadline)
            clock[0] += 19.9
            return {"runtime": {"admission_live": False}}
        runtime.inspect = inspect
        with patch.object(m.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(m.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            with self.assertRaises(m.OperationDeadline):
                runtime.wait_ready(deadline=120)
        self.assertEqual(calls, [120])
        self.assertLessEqual(clock[0], 120)

    def test_cleanup_with_only_five_seconds_does_not_claim_lease_expiry(self):
        runtime = self.runtime()
        child = types.SimpleNamespace(pid=123456, poll=lambda: None, terminate=lambda: None, wait=lambda timeout: 0)
        runtime.process = child
        with patch.object(m.time, "monotonic", return_value=100), \
             patch.object(m.os, "killpg") as kill, patch.object(m.time, "sleep") as sleep:
            with self.assertRaisesRegex(m.OperationDeadline, "lease expiry"):
                runtime.stop(deadline=105)
            kill.assert_called_once()
            sleep.assert_not_called()

    def test_pipeline_start_uses_fixed_runner_not_shell_and_full_rules(self):
        runtime = self.runtime()
        policy = Path(self.cfg["state_dir"]) / "policy-1.json"
        policy.write_text("{}")
        child = types.SimpleNamespace(poll=lambda: None)
        with patch.object(m.subprocess, "Popen", return_value=child) as popen:
            runtime.start(policy, initialize=False)
            command = popen.call_args.args[0]
            self.assertEqual(command[:4], ["/usr/sbin/ip", "netns", "exec", "dpi-web-lab"])
            self.assertIn(str(m.BASE / "service_runner.py"), command)
            self.assertIn("--resume", command)
            self.assertNotIn("--initialize-quiescent", command)
            self.assertIn(str(ROOT / CURRENT["rules"]), command)
            self.assertTrue(popen.call_args.kwargs["start_new_session"])
            self.assertNotIn("shell", popen.call_args.kwargs)
        runtime.log.close()

    def test_forced_stop_kills_only_owned_process_group_then_waits_out_lease(self):
        runtime = self.runtime()
        class Child:
            pid = 123456
            calls = []
            def poll(self): return None
            def terminate(self): self.calls.append("term")
            def wait(self, timeout):
                self.calls.append(("wait", timeout))
                if timeout == 42:
                    raise m.subprocess.TimeoutExpired("fixture", timeout)
                return -9
        runtime.process = Child()
        with patch.object(m.os, "killpg") as kill, patch.object(m.time, "sleep") as sleep:
            runtime.stop()
            kill.assert_called_once_with(123456, m.signal.SIGKILL)
            sleep.assert_called_once_with(5.1)
        self.assertIsNone(runtime.process)

    def test_wrong_namespace_is_rejected_before_any_command_or_map_access(self):
        with patch.object(m.sys, "platform", "linux"), patch.object(m.os, "geteuid", return_value=0), \
             patch.object(m.Path, "exists", return_value=True), \
             patch.object(m.os, "stat", side_effect=[types.SimpleNamespace(st_ino=1), types.SimpleNamespace(st_ino=2)]), \
             patch.object(m.subprocess, "run", side_effect=AssertionError("must not run")):
            with self.assertRaisesRegex(ValueError, "outside the configured"):
                m.runtime_inspect(self.cfg)

    def test_management_interface_in_lab_is_rejected_before_bpf_access(self):
        completed = types.SimpleNamespace(stdout=json.dumps([{"ifname": "lo"}, {"ifname": "eth0"}]))
        with patch.object(m.sys, "platform", "linux"), patch.object(m.os, "geteuid", return_value=0), \
             patch.object(m.Path, "exists", return_value=True), \
             patch.object(m.os, "stat", return_value=types.SimpleNamespace(st_ino=1)), \
             patch.object(m.subprocess, "run", return_value=completed) as run:
            with self.assertRaisesRegex(ValueError, "refusing management"):
                m.runtime_inspect(self.cfg)
            self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
