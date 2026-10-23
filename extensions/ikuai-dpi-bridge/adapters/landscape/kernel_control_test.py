"""Real HTTP policy -> capture -> classifier -> BPF -> veth WAN/native NAT test.
Imported exclusively by linux_routing_test inside its fresh private namespace.
"""
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import threading
import shutil
import time

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("kernel_web_control", BASE / "web_control.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
spec = importlib.util.spec_from_file_location("kernel_web_router", BASE / "router.py")
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)


def verify(args, pins, transmit, expect, packet, report):
    import subprocess
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    root = args.output / "controller"
    root.mkdir(mode=0o700)
    token = "synthetic_kernel_test_control_token_32_chars"
    (root / "control.token").write_text(token); (root / "control.token").chmod(0o600)
    catalog = {"entries": [{"entry_kind": "application_id", "app_id": "42", "application": "Synthetic HTTP app", "translations": []}]}
    rules = {"data": {"_type": "APP", "extend_ik_data": {"_type": "EXTEND_IK_DATA", "exact_host_happs": {"http_app": [{"_type": "IK_HTTP_APP", "appid": 42, "rule_id": 1, "dir": 1, "pkt_seq": 1, "http_info": {"_type": "HTTPINFO", "header": [{"_type": "HTTPHEADER", "index": 1, "data": "app.example.test", "match_method": 0}]}}]}}}}
    for name, value in (("catalog.json", catalog), ("all-rules.json", rules)):
        (root / name).write_text(json.dumps(value))
    mapping = {"metadata": {"source_files": {name: {"bytes": (root / name).stat().st_size, "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest()} for name in ("catalog.json", "all-rules.json")}}, "applications": [{"app_id": "42", "category_path": ["Synthetic", "HTTP"], "rule_count": 1, "domains": ["app.example.test"], "ips": [], "cidrs": [], "domain_patterns": []}]}
    (root / "applications.json").write_text(json.dumps(mapping))
    classifier = root / "dpi-bridge"
    shutil.copyfile(args.controller_binary, classifier); classifier.chmod(0o700)
    config = {"schema_version": 1, "mode": "live", "state_dir": str(root / "state"), "token_file": str(root / "control.token"), "catalog": str(root / "catalog.json"), "application_map": str(root / "applications.json"), "rules": str(root / "all-rules.json"), "binary": str(classifier.resolve()), "clients": ["10.10.10.69"], "interface": "lan0", "pin_root": str(pins / "lan_maps"), "lines": [{"id": "telecom", "name": "Synthetic Telecom", "flow_id": 1, "wan_ifname": "wan1"}, {"id": "unicom", "name": "Synthetic Unicom", "flow_id": 2, "wan_ifname": "wan2"}]}
    cfg = root / "control.json"; cfg.write_text(json.dumps(config)); cfg.chmod(0o600)
    backend = r.RoutingBackend(pins / "lan_maps")
    backend.reset_quiescent()
    control = m.Control(m.load_config(cfg))
    server = m.Server(("127.0.0.1", 0), control, token)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    def request(method, path, body=None, expected=200):
        client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=95)
        try:
            headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
            client.request(method, path, json.dumps(body) if body is not None else None, headers)
            response = client.getresponse(); result = json.loads(response.read())
            assert response.status == expected, (response.status, result)
            return result.get("data", result)
        finally:
            client.close()
    def save(line, revision):
        return request("PUT", "/policy", {"expected_revision": revision, "rules": [{"appid": 42, "line_id": line, "learn_endpoint": True, "allow_udp_endpoint_hints": False}]})
    def hint_flow(flow):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            values = backend.dump("dpi_rt_hint_v1")
            import struct
            if any(struct.unpack("=QIIII", v)[2] == flow for _, v in values):
                return
            time.sleep(.05)
        raise AssertionError("Captured synthetic HTTP did not reach the actual classifier and BPF hint map")
    def learn(sport, wanted):
        expect(sport, 1)
        found = transmit(packet(sport, flags=24, seq=1001, data=b"GET / HTTP/1.1\r\nHost: app.example.test\r\n\r\n"))
        assert [x[0] for x in found] == [1]
        hint_flow(wanted)
    try:
        catalog = request("GET", "/catalog?q=app.example.test")
        assert catalog["items"][0]["category_path"] == ["Synthetic", "HTTP"]
        save("unicom", 0)
        request("POST", "/apply", {"revision": 1, "initial_quiescent": False}, expected=409)
        applied = request("POST", "/apply", {"revision": 1, "initial_quiescent": True})
        assert applied["active_revision"] == 1 and applied["runtime"]["admission_live"]
        time.sleep(.3)  # wait for tcpdump capture setup, distinct from BPF lease readiness
        learn(58000, 2)
        expect(58001, 2)
        report["tests"].append("real HTTP save/apply -> live capture -> Rust classifier -> BPF hint -> next TCP uses WAN2/native SNAT")
        request("PUT", "/policy", {"expected_revision": 0, "rules": []}, expected=409)
        save("telecom", 1)
        resumed = request("POST", "/apply", {"revision": 2, "initial_quiescent": False})
        assert resumed["active_revision"] == 2
        expect(58001, 2, flags=16)
        time.sleep(.3)
        learn(58002, 1)
        expect(58003, 1)
        report["tests"].append("HTTP line change resumed armed maps; existing WAN2 stayed sticky and next learned connection used WAN1")
        stopped = request("POST", "/stop", {})
        assert stopped["active_revision"] is None and not stopped["runtime"]["admission_live"]
        expect(58001, 2, flags=16)
        expect(58004, 1)
        report["tests"].append("HTTP Stop drained actual admission without rewriting existing WAN2; new connection used native default WAN1")
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3); control.close()
