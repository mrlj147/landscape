#!/usr/bin/env python3
"""Accept classifier JSONL; plan or install only the Landscape DPI metadata ABI.

No endpoint calls and no route, Flow, skb mark, DNS or NAT modification.
Run on the same Linux host as Landscape when --apply is explicitly selected.
"""
import argparse
import contextlib
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import time

LABEL_MAP = "dpi_labels_v1"
COUNT_MAP = "dpi_counts_v1"
KEY_SIZE, LABEL_SIZE, COUNT_KEY_SIZE, COUNT_SIZE = 40, 32, 48, 24
MAX_ENTRIES = 65536
LABEL_FLAGS = 128  # BPF_F_RDONLY_PROG


def integer(value, name, lower=0, upper=0xffffffff):
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise ValueError(f"{name} must be an integer in [{lower}, {upper}]")
    return value


def observation_time(value):
    if isinstance(value, bool):
        raise ValueError("observed_at must be Unix seconds or RFC3339")
    if isinstance(value, (int, float)):
        import math
        if not math.isfinite(value):
            raise ValueError("observed_at is not finite")
        return float(value)
    if isinstance(value, str):
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("observed_at requires an explicit timezone")
        return parsed.timestamp()
    raise ValueError("observed_at must be Unix seconds or RFC3339")


def encode_flow(flow):
    if not isinstance(flow, dict) or flow.get("direction") != "lan_to_wan":
        raise ValueError("flow.direction must be lan_to_wan; never guess NAT/reverse tuples")
    version = integer(flow.get("ip_version"), "ip_version", 4, 6)
    if version not in (4, 6):
        raise ValueError("ip_version must be 4 or 6")
    proto = {"tcp": 6, "udp": 17}.get(flow.get("protocol"), flow.get("protocol"))
    if isinstance(proto, bool) or proto not in (6, 17):
        raise ValueError("Only TCP/UDP classification is supported")
    src, dst = ipaddress.ip_address(flow["src_ip"]), ipaddress.ip_address(flow["dst_ip"])
    if src.version != version or dst.version != version:
        raise ValueError("Address families do not match ip_version")
    if getattr(src, "scope_id", None) or getattr(dst, "scope_id", None):
        raise ValueError("Scoped IPv6 addresses require an interface-aware ABI")
    sport = integer(flow.get("src_port"), "src_port", 1, 65535)
    dport = integer(flow.get("dst_port"), "dst_port", 1, 65535)
    return bytes([version, proto, 0, 0]) + src.packed.ljust(16, b"\0") + dst.packed.ljust(16, b"\0") + struct.pack("!HH", sport, dport)


def decode_flow(key):
    if len(key) != KEY_SIZE:
        raise ValueError("Unexpected flow key size")
    version, proto = key[:2]
    size = 4 if version == 4 else 16 if version == 6 else 0
    if not size or proto not in (6, 17) or key[2:4] != b"\0\0":
        raise ValueError("Unexpected flow key ABI")
    sport, dport = struct.unpack("!HH", key[36:40])
    return {"direction": "lan_to_wan", "ip_version": version, "protocol": "tcp" if proto == 6 else "udp",
            "src_ip": str(ipaddress.ip_address(key[4:4+size])), "dst_ip": str(ipaddress.ip_address(key[20:20+size])),
            "src_port": sport, "dst_port": dport}


def load_policy(path):
    if path is None:
        return {}
    policy = json.loads(Path(path).read_text())
    if set(policy) != {"schema_version", "qos_metadata"} or policy["schema_version"] != 1:
        raise ValueError("Policy supports only schema_version=1 and qos_metadata; network actions are forbidden")
    result = {}
    if not isinstance(policy["qos_metadata"], dict):
        raise ValueError("qos_metadata must be an AppID-to-class object")
    for appid, entry in policy["qos_metadata"].items():
        appid = integer(int(appid), "policy AppID", 1)
        if not isinstance(entry, dict) or set(entry) != {"approved", "class_id"} or entry["approved"] is not True:
            raise ValueError("Each QoS metadata mapping requires explicit approved=true and class_id")
        result[appid] = integer(entry["class_id"], "class_id", 1)
    return result


def plan(event, policy=None, ttl=120, now=None, monotonic_ns=None, max_age=30):
    now = time.time() if now is None else now
    monotonic_ns = time.monotonic_ns() if monotonic_ns is None else monotonic_ns
    if not isinstance(event, dict) or type(event.get("schema_version")) is not int or event.get("schema_version") != 1 or event.get("event") not in ("classification", "retraction"):
        raise ValueError("Expected schema_version=1 classification or retraction event")
    retract = event["event"] == "retraction"
    appid = integer(event.get("appid"), "appid") if not retract else None
    if appid == 0:
        return {"status": "ignored_unknown", "network_action": "none"}
    rule_id = integer(event.get("rule_id"), "rule_id") if not retract else None
    key = encode_flow(event.get("flow"))
    observed = observation_time(event.get("observed_at"))
    if observed > now + 5 or now - observed > max_age:
        raise ValueError("Stale/future observation; replay must not label a reused live five-tuple")
    if retract:
        return {"status": "planned_delete", "operation": "delete", "map": LABEL_MAP,
                "key_hex": key.hex(), "flow": decode_flow(key), "network_action": "none",
                "observed_at_seconds": observed}
    ttl = integer(ttl, "ttl", 1, 3600)
    generation = integer(monotonic_ns, "monotonic_ns", 1, (1 << 64) - 1)
    expires = generation + ttl * 1_000_000_000
    if expires >= (1 << 64):
        raise ValueError("Expiry overflow")
    qos = (policy or {}).get(appid, 0)
    value = struct.pack("=QQIIII", expires, generation, appid, rule_id, qos, 0)
    return {"status": "planned", "map": LABEL_MAP, "key_hex": key.hex(), "value_hex": value.hex(),
            "appid": appid, "rule_id": rule_id, "qos_class_metadata": qos,
            "network_action": "none", "flow": decode_flow(key), "expires_monotonic_ns": expires,
            "observed_at_seconds": observed}


class EventReceiver:
    """One continuous producer session, with bounded ordering/tombstone state.

    plan() is deliberately stateless. CLI consumers must use this layer so
    delayed events cannot undo newer metadata within a running session.
    """
    def __init__(self, policy=None, ttl=120, max_age=30, max_flows=MAX_ENTRIES, backend=None):
        self.policy, self.backend = policy, backend
        self.ttl = integer(ttl, "ttl", 1, 3600)
        self.max_age = integer(max_age, "max_age", 0, 3600)
        self.max_flows = integer(max_flows, "max_flows", 1, MAX_ENTRIES)
        self.retention_ns = max(self.ttl, self.max_age + 5) * 1_000_000_000
        self.watermarks = {}  # key -> (observed wall time, retracted, expiry monotonic time)
        self.last_gc_ns = 0

    def _expire(self, now_ns):
        self.watermarks = {k: v for k, v in self.watermarks.items() if v[2] > now_ns}
        self.last_gc_ns = now_ns

    def process(self, event, now=None, monotonic_ns=None):
        now_ns = time.monotonic_ns() if monotonic_ns is None else monotonic_ns
        integer(now_ns, "monotonic_ns", 1, (1 << 64) - 1)
        item = plan(event, self.policy, self.ttl, now, now_ns, self.max_age)
        if item["status"] not in ("planned", "planned_delete"):
            return item
        key, observed = item["key_hex"], item["observed_at_seconds"]
        retract = item["status"] == "planned_delete"
        if now_ns >= self.last_gc_ns + 1_000_000_000:
            self._expire(now_ns)
        previous = self.watermarks.get(key)
        if previous is not None and previous[2] <= now_ns:
            del self.watermarks[key]
            previous = None
        if previous is not None:
            if observed < previous[0] or (observed == previous[0] and previous[1] and not retract):
                return {"status": "ignored_out_of_order", "flow": item["flow"], "network_action": "none"}
            # Duplicate classifications must not extend the TTL from receive time.
            if observed == previous[0] and not retract:
                return {"status": "ignored_duplicate", "flow": item["flow"], "network_action": "none"}
        if previous is None and len(self.watermarks) >= self.max_flows:
            self._expire(now_ns)
            if len(self.watermarks) >= self.max_flows:
                raise ValueError("Flow/tombstone limit reached; refusing unbounded session state")
        result = self.backend.install(item, now_ns=now_ns) if self.backend else item
        # Commit ordering only after a successful backend operation. Failure must
        # remain retryable; conflicting labels still advance the observation time.
        self.watermarks[key] = (observed, retract, now_ns + self.retention_ns)
        return result


class WriterLock:
    """Process lifetime lock for cooperating writers to one canonical pin root."""
    def __init__(self, pin_root, lock_dir=Path("/run/landscape-dpi-bridge")):
        self.pin_root = Path(pin_root).resolve()
        self.lock_dir = Path(lock_dir)
        self.fd = None

    def __enter__(self):
        import fcntl
        self.lock_dir.mkdir(mode=0o700, exist_ok=True)
        info = self.lock_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("Writer lock directory must be owned by this user with mode 0700 and not be a symlink")
        name = hashlib.sha256(str(self.pin_root).encode()).hexdigest() + ".lock"
        self.fd = os.open(self.lock_dir / name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError("Unsafe writer lock file ownership or mode")
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError("Another receiver already writes this pin-root") from exc
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise
        return self

    def __exit__(self, *_):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def raw_bytes(value):
    if isinstance(value, str):
        return bytes.fromhex(value)
    if isinstance(value, list):
        return bytes(int(x, 16) if isinstance(x, str) else x for x in value)
    raise ValueError("Expected raw bpftool bytes; BTF-formatted maps are not ABI v1")


class Bpftool:
    def __init__(self, pin_root, executable="bpftool", runner=subprocess.run):
        self.pin_root = Path(pin_root)
        if not self.pin_root.is_absolute() or ".." in self.pin_root.parts or not str(self.pin_root).startswith("/sys/fs/bpf/landscape/"):
            raise ValueError("pin_root must be an explicit /sys/fs/bpf/landscape/<space> directory")
        self.pin_root = self.pin_root.resolve()
        if not str(self.pin_root).startswith("/sys/fs/bpf/landscape/"):
            raise ValueError("pin_root must not resolve outside the Landscape bpffs root")
        self.executable, self.runner = executable, runner

    def assert_no_live_labels(self, now_ns=None):
        """Call only while holding WriterLock; never clear an earlier session."""
        now_ns = time.monotonic_ns() if now_ns is None else now_ns
        self.check(LABEL_MAP)
        for row in self.command("map", "dump", "pinned", str(self.pin_root / LABEL_MAP)):
            key, value = raw_bytes(row["key"]), raw_bytes(row["value"])
            if len(key) != KEY_SIZE or len(value) != LABEL_SIZE:
                raise ValueError("Unexpected label ABI at session start")
            if struct.unpack_from("=Q", value)[0] > now_ns:
                raise RuntimeError("Unexpired labels remain from another session; wait for their TTL to expire, then start a fresh producer. No labels were changed.")

    def command(self, *args, allow_missing=False):
        r = self.runner([self.executable, "-j", *args], capture_output=True, text=True, check=False)
        # bpftool do_lookup emits JSON null for ENOENT; every other error fails.
        # Source: libbpf/bpftool src/map.c do_lookup(), not stderr substring guessing.
        if allow_missing and r.returncode and r.stdout.strip() == "null" and not r.stderr.strip():
            return None
        if r.returncode:
            raise RuntimeError(f"bpftool operation failed: {r.stderr.strip()[:300]}")
        return json.loads(r.stdout) if r.stdout.strip() else None

    def check(self, name):
        expected = {LABEL_MAP: (KEY_SIZE, LABEL_SIZE, LABEL_FLAGS), COUNT_MAP: (COUNT_KEY_SIZE, COUNT_SIZE, 0)}
        if name not in expected:
            raise ValueError("Not a DPI metadata map")
        info = self.command("map", "show", "pinned", str(self.pin_root / name))
        if isinstance(info, list):
            if len(info) != 1:
                raise ValueError("Ambiguous map")
            info = info[0]
        k, v, flags = expected[name]
        if not isinstance(info, dict) or (info.get("name"), info.get("type"), info.get("bytes_key"), info.get("bytes_value"), info.get("max_entries"), info.get("flags")) != (name, "lru_hash", k, v, MAX_ENTRIES, flags):
            raise ValueError(f"Map ABI mismatch for {name}")

    def install(self, item, now_ns=None):
        if item["status"] not in ("planned", "planned_delete"):
            return item
        self.check(LABEL_MAP)
        key = bytes.fromhex(item["key_hex"])
        old_row = self.command("map", "lookup", "pinned", str(self.pin_root / LABEL_MAP),
                               "key", "hex", *key.hex(" ").split(), allow_missing=True)
        if item["status"] == "planned_delete":
            if old_row is None:
                return {**item, "status": "already_absent"}
            if raw_bytes(old_row["key"]) != key:
                raise ValueError("Lookup returned a different flow key")
            self.command("map", "delete", "pinned", str(self.pin_root / LABEL_MAP),
                         "key", "hex", *key.hex(" ").split())
            return {**item, "status": "retracted"}
        value = bytes.fromhex(item["value_hex"])
        now_ns = time.monotonic_ns() if now_ns is None else now_ns
        status = "installed"
        if struct.unpack_from("=Q", value)[0] <= now_ns:
            raise ValueError("Planned label expired before installation")
        update_mode = "noexist"
        if old_row is not None:
            if raw_bytes(old_row["key"]) != key:
                raise ValueError("Lookup returned a different flow key")
            old = raw_bytes(old_row["value"])
            if len(old) != LABEL_SIZE:
                raise ValueError("Unexpected existing label ABI")
            expires, generation, appid, rule_id, qos, reserved = struct.unpack("=QQIIII", old)
            if expires > now_ns:
                if (appid, rule_id) != (item["appid"], item["rule_id"]):
                    return {**item, "status": "kept_existing_label", "existing_appid": appid}
                value = struct.pack("=QQIIII", item["expires_monotonic_ns"], generation, appid, rule_id,
                                    item["qos_class_metadata"], 0)
                status = "refreshed"
            update_mode = "exist"
        self.command("map", "update", "pinned", str(self.pin_root / LABEL_MAP), "key", "hex", *key.hex(" ").split(), "value", "hex", *value.hex(" ").split(), update_mode)
        return {**item, "value_hex": value.hex(), "status": status}

    def counters(self):
        self.check(COUNT_MAP)
        self.check(LABEL_MAP)
        labels = {}
        for row in self.command("map", "dump", "pinned", str(self.pin_root / LABEL_MAP)):
            key, value = raw_bytes(row["key"]), raw_bytes(row["value"])
            if len(key) != KEY_SIZE or len(value) != LABEL_SIZE:
                raise ValueError("Unexpected label ABI")
            expiry, generation, appid, rule_id, qos, reserved = struct.unpack("=QQIIII", value)
            labels[(key, generation)] = {"appid": appid, "rule_id": rule_id,
                                         "qos_class_metadata": qos, "expired": expiry <= time.monotonic_ns()}
        rows = self.command("map", "dump", "pinned", str(self.pin_root / COUNT_MAP))
        result = []
        for row in rows:
            key, value = raw_bytes(row["key"]), raw_bytes(row["value"])
            if len(key) != COUNT_KEY_SIZE or len(value) != COUNT_SIZE:
                raise ValueError("Unexpected counter ABI")
            packets, size, seen = struct.unpack("=QQQ", value)
            generation = struct.unpack("=Q", key[40:])[0]
            result.append({"flow": decode_flow(key[:40]), "generation": generation,
                           "label_metadata": labels.get((key[:40], generation)),
                           "packets_after_label": packets, "bytes_after_label": size, "last_seen_monotonic_ns": seen})
        return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apply", action="store_true", help="Explicitly write only the patched DPI label map")
    ap.add_argument("--replay", action="store_true", help="Offline dry-run only: evaluate event age at its packet timestamp")
    ap.add_argument("--pin-root", help="Required for apply/counters, e.g. /sys/fs/bpf/landscape/default")
    ap.add_argument("--policy", type=Path)
    ap.add_argument("--ttl", type=int, default=120)
    ap.add_argument("--max-age", type=int, default=30)
    ap.add_argument("--max-flows", type=int, default=MAX_ENTRIES, help="Bound combined active ordering records and retraction tombstones")
    ap.add_argument("--counters", action="store_true")
    args = ap.parse_args(argv)
    if args.replay and (args.apply or args.counters):
        ap.error("--replay is incompatible with --apply/--counters")
    policy = load_policy(args.policy)
    backend = None
    if args.apply or args.counters:
        if sys.platform != "linux" or not args.pin_root:
            ap.error("Apply/counters require Linux and explicit --pin-root")
        backend = Bpftool(args.pin_root)
    if args.counters:
        print(json.dumps(backend.counters()))
        return 0
    with contextlib.ExitStack() as session:
        if args.apply:
            try:
                session.enter_context(WriterLock(backend.pin_root))
                backend.assert_no_live_labels()
            except (OSError, ValueError, RuntimeError) as exc:
                ap.error(str(exc))
        receiver = EventReceiver(policy, args.ttl, args.max_age, args.max_flows, backend)
        return consume(receiver, replay=args.replay)


def consume(receiver, replay=False):
    failed = False
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            if len(line) > 1_000_000:
                raise ValueError("Event exceeds 1 MiB")
            event = json.loads(line)
            replay_now = observation_time(event.get("observed_at")) if replay else None
            item = receiver.process(event, now=replay_now)
            if replay:
                item["replay_only"] = True
            print(json.dumps(item, ensure_ascii=False), flush=True)
        except (ValueError, KeyError, TypeError, RuntimeError) as e:
            failed = True
            print(json.dumps({"status": "rejected", "error": str(e), "network_action": "none"}), flush=True)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
