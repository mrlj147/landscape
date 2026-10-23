#!/usr/bin/env python3
"""Controlled Landscape application -> Flow/WAN admission, with no mid-flow reroute.

Default is dry-run JSONL. --apply writes only the patched independent maps.
Exact clients and explicit approved AppID mappings are mandatory. Learned
endpoint hints are opt-in and heuristic; TCP needs a new SYN, UDP also requires
an explicit policy opt-in. The BPF route map alone locks active decisions.
"""
import argparse
import contextlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import selectors
import socket
import struct
import sys
import time

BASE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("landscape_metadata", BASE / "receiver.py")
r = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(r)
MAPS = {
    "dpi_rt_cfg_v1": ("array", 4, 16, 1, 128),
    "dpi_rt_cli_v1": ("hash", 20, 4, 256, 128),
    "dpi_rt_hint_v1": ("hash", 40, 24, 65536, 128),
    "dpi_rt_flow_v1": ("hash", 40, 96, 65536, 0),
    "dpi_rt_nat_v1": ("hash", 4, 16, 1024, 128),
}
NS = 1_000_000_000

def client_key(address):
    ip = ipaddress.ip_address(address)
    if getattr(ip, "scope_id", None): raise ValueError("Scoped client is unsupported")
    return struct.pack("=I", ip.version) + ip.packed.ljust(16, b"\0")

def endpoint_key(flow):
    key = bytearray(r.encode_flow(flow)); key[36:38] = b"\0\0"
    return bytes(key)

def policy_load(path):
    value = json.loads(Path(path).read_text()) if not isinstance(path, dict) else path
    allowed = {"schema_version", "clients", "applications", "static_endpoints", "hint_ttl_seconds"}
    if set(value) - allowed or value.get("schema_version") != 1:
        raise ValueError("Unknown routing policy schema/field")
    clients = value.get("clients", [])
    if not isinstance(clients, list) or not clients or len(clients) > 256:
        raise ValueError("One to 256 exact client addresses required")
    clients = sorted({str(ipaddress.ip_address(x)) for x in clients})
    for client in clients:
        client_key(client)
        if ipaddress.ip_address(client).version != 4: raise ValueError("IPv6 application routing is disabled until ISP source-prefix policy is validated")
    ttl = r.integer(value.get("hint_ttl_seconds", 30), "hint_ttl_seconds", 1, 120)
    apps = {}
    for raw_id, item in value.get("applications", {}).items():
        appid = r.integer(int(raw_id), "AppID", 1)
        fields = {"approved", "flow_id", "wan_ifname", "learn_endpoint", "allow_udp_endpoint_hints"}
        if not isinstance(item, dict) or set(item) != fields or item["approved"] is not True:
            raise ValueError("App mappings require exactly approved, flow_id, wan_ifname, learn_endpoint, allow_udp_endpoint_hints")
        flow_id = r.integer(item["flow_id"], "flow_id", 1, 255)
        if not isinstance(item["wan_ifname"], str) or not item["wan_ifname"] or len(item["wan_ifname"]) > 15:
            raise ValueError("Expected Linux WAN interface name")
        if type(item["learn_endpoint"]) is not bool or type(item["allow_udp_endpoint_hints"]) is not bool:
            raise ValueError("Hint permissions must be booleans")
        apps[appid] = {**item, "flow_id": flow_id}
    static = {}
    for item in value.get("static_endpoints", []):
        if set(item) != {"appid", "client", "destination", "protocol", "port"}:
            raise ValueError("Unknown static endpoint field")
        appid = r.integer(item["appid"], "static AppID", 1)
        if appid not in apps or item["client"] not in clients:
            raise ValueError("Static endpoint must use an approved app/client")
        src, dst = ipaddress.ip_address(item["client"]), ipaddress.ip_address(item["destination"])
        flow = dict(direction="lan_to_wan", ip_version=src.version, protocol=item["protocol"],
                    src_ip=str(src), src_port=1, dst_ip=str(dst), dst_port=item["port"])
        key = endpoint_key(flow)
        if key in static and static[key] != appid: raise ValueError("Conflicting static endpoint")
        if key[1] == 17 and not apps[appid]["allow_udp_endpoint_hints"]:
            raise ValueError("UDP static endpoint also needs explicit allow_udp_endpoint_hints")
        static[key] = appid
    return {"clients": clients, "applications": apps, "static": static, "ttl": ttl}

class RoutingBackend(r.Bpftool):
    def check_routes(self):
        for name, expected in MAPS.items():
            info = self.command("map", "show", "pinned", str(self.pin_root / name))
            if isinstance(info, list): info = info[0] if len(info) == 1 else {}
            actual = tuple(info.get(x) for x in ("type", "bytes_key", "bytes_value", "max_entries", "flags"))
            if info.get("name") != name or actual != expected:
                raise ValueError("Routing map ABI mismatch: " + name)
    def dump(self, name):
        if name not in MAPS: raise ValueError("Not an owned routing map")
        result = []
        for row in self.command("map", "dump", "pinned", str(self.pin_root / name)):
            key, val = r.raw_bytes(row["key"]), r.raw_bytes(row["value"])
            if len(key) != MAPS[name][1] or len(val) != MAPS[name][2]: raise ValueError("Bad map entry ABI")
            result.append((key, val))
        return result
    def put(self, name, key, value):
        if name not in MAPS or len(key) != MAPS[name][1] or len(value) != MAPS[name][2]:
            raise ValueError("Invalid owned map write")
        self.command("map", "update", "pinned", str(self.pin_root / name), "key", "hex", *key.hex(" ").split(),
                     "value", "hex", *value.hex(" ").split(), "any")
    def delete(self, name, key):
        if name not in MAPS or name == "dpi_rt_cfg_v1": raise ValueError("Not a deletable owned map")
        # Check under the sole writer lock; flow records are never deleted while traffic runs.
        found = self.command("map", "lookup", "pinned", str(self.pin_root / name), "key", "hex", *key.hex(" ").split(), allow_missing=True)
        if found is not None:
            self.command("map", "delete", "pinned", str(self.pin_root / name), "key", "hex", *key.hex(" ").split())
    def config(self, armed, admit, lease_ns=0):
        self.put("dpi_rt_cfg_v1", struct.pack("=I", 0), struct.pack("=IIQ", armed, admit, lease_ns))
    def check_wan(self, app, version):
        cache = getattr(self, "_wan_cache", {})
        cache_key = (app["flow_id"], app["wan_ifname"], version)
        if cache.get(cache_key, 0) > time.monotonic_ns(): return
        expected_ifindex = socket.if_nametoindex(app["wan_ifname"])
        name = "rt%d_slot_map" % version
        info = self.command("map", "show", "pinned", str(self.pin_root / name))
        if isinstance(info, list): info = info[0] if len(info) == 1 else {}
        size = 20 if version == 4 else 32
        if info.get("type") != "hash" or info.get("bytes_key") != 8 or info.get("bytes_value") != size:
            raise ValueError("Unexpected Landscape route slot ABI")
        targets = []
        for slot in range(16):
            key = struct.pack("=II", app["flow_id"], slot)
            row = self.command("map", "lookup", "pinned", str(self.pin_root / name), "key", "hex", *key.hex(" ").split(), allow_missing=True)
            if row is None: raise ValueError("Approved Flow is missing a WAN slot")
            raw = r.raw_bytes(row["value"])
            if len(raw) != size: raise ValueError("Route slot size changed")
            ifindex = struct.unpack_from("=I", raw)[0]
            has_mac_offset = 8 if version == 4 else 20
            if ifindex != expected_ifindex or raw[has_mac_offset + 1] != 0:
                raise ValueError("Flow is not exclusively mapped to the approved physical WAN")
            chain = struct.unpack_from("=H", raw, 16 if version == 4 else 28)[0]
            ready = self.command("map", "lookup", "pinned", str(self.pin_root / "dpi_rt_nat_v1"),
                                 "key", "hex", *struct.pack("=I", chain).hex(" ").split(), allow_missing=True)
            if ready is None or struct.unpack_from("=I", r.raw_bytes(ready["value"]))[0] != ifindex:
                raise ValueError("Approved WAN has no registered native NAT4 lifecycle hook")
            targets.append(raw)
        if len(set(targets)) != 1: raise ValueError("Application Flow must have one identical target in all 16 slots")
        cache[cache_key] = time.monotonic_ns() + 3 * NS
        self._wan_cache = cache
    def initialize(self, policy, quiescent=False, resume=False):
        self.check_routes()
        cfg = self.dump("dpi_rt_cfg_v1")[0][1]
        armed, admit, lease = struct.unpack("=IIQ", cfg)
        if lease > time.monotonic_ns() and admit: raise RuntimeError("Another producer lease is still active")
        clients = {k for k, _ in self.dump("dpi_rt_cli_v1")}
        requested = {client_key(c) for c in policy["clients"]}
        flows = self.dump("dpi_rt_flow_v1")
        if armed:
            if not resume or clients != requested: raise RuntimeError("Armed map requires --resume with exactly the same client set; route decisions are retained")
        elif not quiescent or flows:
            raise RuntimeError("Initial arm requires --initialize-quiescent and an empty route map")
        for app in policy["applications"].values():
            for version in {ipaddress.ip_address(c).version for c in policy["clients"]}: self.check_wan(app, version)
        self.config(armed, 0)
        for key, _ in self.dump("dpi_rt_hint_v1"): self.delete("dpi_rt_hint_v1", key)
        if not armed:
            # A crash during an earlier first arm can leave client entries
            # while cfg is still unarmed. Never expand a new client's scope.
            for key in clients - requested: self.delete("dpi_rt_cli_v1", key)
        for key in requested: self.put("dpi_rt_cli_v1", key, struct.pack("=I", 1))
        self.config(1, 0)
    def status(self):
        cfg = self.dump("dpi_rt_cfg_v1")[0][1]
        armed, admit, lease = struct.unpack("=IIQ", cfg)
        flows = []
        for key, raw in self.dump("dpi_rt_flow_v1"):
            created, seen, mark, appid, nat_token, seq, flags = struct.unpack_from("=QQIIQII", raw)
            ifindex = struct.unpack_from("=I", raw, 48)[0]
            chain_id = struct.unpack_from("=H", raw, 76)[0]
            flows.append({"flow": r.decode_flow(key), "appid_at_admission": appid,
                          "flow_id": mark & 255, "mark": mark, "wan_ifindex": ifindex,
                          "wan_chain_id": chain_id, "nat_session_token": nat_token, "nat_instance_epoch": struct.unpack_from("=Q", raw, 40)[0], "created_tai_ns": created, "last_seen_ns": seen})
        return {"armed": bool(armed), "admission_live": bool(admit and lease > time.monotonic_ns()),
                "pinned_connections": flows, "automatic_gc": "Landscape NAT4 conntrack lifecycle"}
    def reset_quiescent(self):
        # Explicit maintenance only. Caller must stop selected-client traffic first.
        self.config(1, 0)
        for name in ("dpi_rt_flow_v1", "dpi_rt_hint_v1", "dpi_rt_cli_v1"):
            for key, _ in self.dump(name): self.delete(name, key)
        self.config(0, 0)

class HintReceiver:
    def __init__(self, policy, backend=None):
        self.policy, self.backend = policy, backend
        self.order = r.EventReceiver(ttl=policy["ttl"], max_age=30)
        self.records = {}  # exact flow -> (endpoint, appid, expires); no raw payload retained
        self.applied = {}
        self.lease_deadline = None
    def refresh(self, now_ns=None):
        now_ns = time.monotonic_ns() if now_ns is None else now_ns
        self.records = {k: v for k, v in self.records.items() if v[2] > now_ns}
        aggregate = {}
        for endpoint, appid, expires in self.records.values():
            aggregate.setdefault(endpoint, {})[appid] = min(expires, aggregate.get(endpoint, {}).get(appid, expires))
        desired = {}
        for endpoint, ids in aggregate.items():
            if len(ids) == 1:
                appid, expires = next(iter(ids.items())); desired[endpoint] = (appid, expires)
        for endpoint, appid in self.policy["static"].items(): desired[endpoint] = (appid, now_ns + self.policy["ttl"] * NS)
        desired = {key: value for key, value in desired.items() if value[0] in self.policy["applications"]}
        changes = []
        for key in self.applied.keys() - desired.keys():
            if self.backend: self.backend.delete("dpi_rt_hint_v1", key)
            changes.append({"operation": "withdraw_future_hint", "endpoint_key": key.hex()})
        next_applied = {}
        for key, (appid, expiry) in desired.items():
            app = self.policy["applications"].get(appid)
            if app is None: continue
            if self.backend: self.backend.check_wan(app, key[0])
            flags = int(app["allow_udp_endpoint_hints"])
            value = struct.pack("=QIIII", expiry, appid, app["flow_id"], flags, 0)
            if self.applied.get(key) != value:
                if self.backend: self.backend.put("dpi_rt_hint_v1", key, value)
                changes.append({"operation": "hint_for_new_connections", "endpoint_key": key.hex(), "appid": appid,
                                "flow_id": app["flow_id"], "expires_monotonic_ns": expiry,
                                "heuristic": key not in self.policy["static"]})
            next_applied[key] = value
        self.applied = next_applied
        if self.backend:
            completed = time.monotonic_ns()
            self.lease_deadline = completed + 5 * NS
            self.backend.config(1, 1, self.lease_deadline)
        return changes
    def process(self, event, now=None, now_ns=None):
        now_ns = time.monotonic_ns() if now_ns is None else now_ns
        item = self.order.process(event, now=now, monotonic_ns=now_ns)
        if item["status"] not in ("planned", "planned_delete"): return item
        key = bytes.fromhex(item["key_hex"])
        if item["flow"]["src_ip"] not in self.policy["clients"]:
            return {"status": "ignored_unapproved_client", "current_connection_action": "unchanged"}
        if item["status"] == "planned_delete": self.records.pop(key, None)
        else:
            appid = item["appid"]; app = self.policy["applications"].get(appid)
            if not app or not app["learn_endpoint"]:
                # A different/unknown app at a shared endpoint invalidates a learned hint.
                self.records[key] = (endpoint_key(item["flow"]), 0, now_ns + self.policy["ttl"] * NS)
            else:
                self.records[key] = (endpoint_key(item["flow"]), appid, now_ns + self.policy["ttl"] * NS)
        return {"status": "accepted", "current_connection_action": "unchanged", "changes": self.refresh(now_ns)}

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--policy", type=Path)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="Suppress per-flow success logs during supervised live capture")
    ap.add_argument("--pin-root")
    ap.add_argument("--initialize-quiescent", action="store_true")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--drain", action="store_true", help="Disable new app admissions; retain all connection decisions")
    ap.add_argument("--reset-quiescent", action="store_true", help="Explicit maintenance: clients must be stopped before clearing owned maps")
    ap.add_argument("--status", action="store_true")
    args = ap.parse_args(argv)
    if args.quiet and not args.apply: ap.error("--quiet is for supervised --apply only")
    control = args.drain or args.reset_quiescent or args.status
    if (args.initialize_quiescent or args.resume or control) and not args.apply: ap.error("Control actions require --apply")
    if args.apply and (sys.platform != "linux" or not args.pin_root): ap.error("--apply needs Linux and explicit --pin-root")
    if not control and not args.policy: ap.error("--policy is required")
    backend = RoutingBackend(args.pin_root) if args.apply else None
    policy = policy_load(args.policy) if args.policy else None
    if args.status:
        backend.check_routes(); print(json.dumps(backend.status())); return 0
    with contextlib.ExitStack() as stack:
        if backend:
            stack.enter_context(r.WriterLock(backend.pin_root)); backend.check_routes()
            if args.drain: backend.config(1, 0); print('{"status":"draining","existing_connections":"retained"}'); return 0
            if args.reset_quiescent: backend.reset_quiescent(); print('{"status":"reset_after_explicit_quiescence"}'); return 0
            backend.initialize(policy, args.initialize_quiescent, args.resume)
        receiver = HintReceiver(policy, backend)
        failed = False
        try:
            receiver.refresh()
            if not backend:
                for line in sys.stdin:
                    if not line.strip(): continue
                    try: print(json.dumps(receiver.process(json.loads(line))), flush=True)
                    except (ValueError, KeyError, TypeError, RuntimeError) as exc:
                        failed = True; print(json.dumps({"status":"rejected", "error":str(exc)}), flush=True)
            else:
                # select + os.read avoids TextIO prefetch leaving complete JSON lines hidden.
                selector = selectors.DefaultSelector(); selector.register(sys.stdin, selectors.EVENT_READ)
                buffer = b""
                while True:
                    ready = selector.select(1)
                    receiver.refresh()
                    if not ready: continue
                    block = os.read(sys.stdin.fileno(), 65536)
                    if not block:
                        if buffer.strip(): raise ValueError("Truncated JSONL event at EOF")
                        break
                    buffer += block
                    if len(buffer) > 1_000_000: raise ValueError("Event input buffer exceeds 1 MiB")
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        if line.strip():
                            result = receiver.process(json.loads(line))
                            if not args.quiet: print(json.dumps(result), flush=True)
        finally:
            if backend: backend.config(1, 0)
        return int(failed)
if __name__ == "__main__": raise SystemExit(main())
