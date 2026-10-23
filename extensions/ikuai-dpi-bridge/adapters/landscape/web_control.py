#!/usr/bin/env python3
"""Authenticated, loopback-only application policy control for Landscape.

Preview mode performs file operations only. Lab mode uses one immutable isolated
network namespace and the existing supervised full-library classifier pipeline.
Saving a policy is never reported as a successful kernel application.
"""
import argparse
import contextlib
import copy
import hmac
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

BASE = Path(__file__).resolve().parent
MAX_BODY = 1 << 20
MAX_RULES = 4096
PORT = 6310
APPLY_SECONDS = 85
WORK_SECONDS = 70
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


class ControlError(Exception):
    def __init__(self, message, status=400, error_id="invalid_request"):
        super().__init__(message)
        self.status, self.error_id = status, error_id


class OperationDeadline(RuntimeError):
    pass


def time_limit(deadline, maximum):
    """Check *before* each blocking call or mutation, not after it completed."""
    if deadline is None:
        return maximum
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise OperationDeadline("Operation deadline expired; no further application steps were started")
    return min(maximum, remaining)


def integer(value, field, lower=0, upper=2**53 - 1):
    if type(value) is not int or not lower <= value <= upper:
        raise ControlError(f"{field} must be an integer between {lower} and {upper}")
    return value


def exact_fields(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ControlError("Unexpected or missing request fields")


def secure_file(path, private=False):
    path = Path(path)
    info = path.lstat()
    forbidden = 0o077 if private else 0o022
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & forbidden:
        raise ValueError(f"Unsafe file ownership or permissions: {path}")
    return path


def absolute(value, field):
    if not isinstance(value, str) or not Path(value).is_absolute() or ".." in Path(value).parts:
        raise ValueError(f"{field} must be an absolute path without parent traversal")
    return Path(value)


def load_config(path):
    path = secure_file(absolute(str(path), "config"))
    value = json.loads(path.read_text())
    common = {"schema_version", "mode", "state_dir", "token_file", "catalog", "clients", "lines"}
    extra = {"netns", "interface", "pin_root", "rules", "binary", "max_flows", "application_map"}
    if not isinstance(value, dict) or set(value) - common - extra or not common <= set(value):
        raise ValueError("Unknown or missing control configuration fields")
    if value["schema_version"] != 1 or type(value["schema_version"]) is not int:
        raise ValueError("Unsupported control configuration schema")
    if value["mode"] not in ("preview", "lab", "live"):
        raise ValueError("Choose preview, isolated lab or explicitly configured live mode")
    for name in ("state_dir", "token_file", "catalog"):
        absolute(value[name], name)
    if not isinstance(value["clients"], list) or not 1 <= len(value["clients"]) <= 256:
        raise ValueError("One to 256 fixed IPv4 clients required")
    clients = [str(ipaddress.IPv4Address(c)) for c in value["clients"]]
    if any(ipaddress.IPv4Address(c).is_multicast or ipaddress.IPv4Address(c).is_loopback or ipaddress.IPv4Address(c).is_unspecified or ipaddress.IPv4Address(c).is_reserved for c in clients):
        raise ValueError("Client scope cannot contain multicast, loopback, unspecified or reserved addresses")
    if len(set(clients)) != len(clients):
        raise ValueError("Duplicate fixed clients")
    value["clients"] = sorted(clients)
    if not isinstance(value["lines"], list) or len(value["lines"]) != 2:
        raise ValueError("Exactly two fixed lines required")
    for line in value["lines"]:
        exact_fields(line, ("id", "name", "flow_id", "wan_ifname"))
        if line["id"] not in ("telecom", "unicom") or not isinstance(line["name"], str) or not 1 <= len(line["name"]) <= 80:
            raise ValueError("Invalid fixed line")
        integer(line["flow_id"], "flow_id", 1, 255)
        if not isinstance(line["wan_ifname"], str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", line["wan_ifname"]):
            raise ValueError("Invalid fixed WAN interface")
    if {x["id"] for x in value["lines"]} != {"telecom", "unicom"}:
        raise ValueError("Duplicate fixed line IDs")
    if len({x["flow_id"] for x in value["lines"]}) != 2 or len({x["wan_ifname"] for x in value["lines"]}) != 2:
        raise ValueError("Selectable lines must have distinct Flow IDs and WAN interfaces")
    if value["mode"] == "lab":
        required = extra - {"max_flows", "application_map"}
        if not required <= set(value):
            raise ValueError("Missing isolated lab configuration")
        if value["netns"] != "dpi-web-lab" or value["interface"] != "lan0":
            raise ValueError("Only the isolated dpi-web-lab/lan0 deployment is supported")
        if value["pin_root"] != "/sys/fs/bpf/landscape/dpi-web-lab/lan_maps":
            raise ValueError("Lab cannot use the management Landscape map namespace")
        if clients != ["10.10.10.69"]:
            raise ValueError("Lab uses only its fixed synthetic client")
        expected = {"telecom": (1, "wan1"), "unicom": (2, "wan2")}
        if any((x["flow_id"], x["wan_ifname"]) != expected[x["id"]] for x in value["lines"]):
            raise ValueError("Lab line mappings differ from the isolated fixture")
        absolute(value["rules"], "rules")
        absolute(value["binary"], "binary")
        integer(value.get("max_flows", 4096), "max_flows", 1, 65536)
    if value["mode"] == "live":
        required = {"interface", "pin_root", "rules", "binary", "application_map"}
        if not required <= set(value) or "netns" in value:
            raise ValueError("Live mode needs explicit interface/maps/library/binary and cannot select a namespace")
        if not isinstance(value["interface"], str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", value["interface"]) or value["interface"] in ("lo", "any"):
            raise ValueError("An explicit Ethernet LAN capture interface is required")
        if value["interface"] in {x["wan_ifname"] for x in value["lines"]}:
            raise ValueError("LAN capture cannot use a configured WAN")
        pin = absolute(value["pin_root"], "pin_root")
        if not pin.is_relative_to("/sys/fs/bpf/landscape"):
            raise ValueError("Live maps must belong to the configured Landscape bpffs tree")
        for name in ("rules", "binary", "application_map"):
            absolute(value[name], name)
        integer(value.get("max_flows", 4096), "max_flows", 1, 65536)
        verify_library(value)
    if "application_map" in value:
        absolute(value["application_map"], "application_map")
    value["_config_path"] = str(path.resolve())
    return value


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".pending")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(value, f, ensure_ascii=False, separators=(",", ":"))
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def verify_library(config):
    for name, bound in (("catalog", 8 << 20), ("rules", 64 << 20), ("application_map", 16 << 20)):
        source = secure_file(config[name])
        if not 0 < source.stat().st_size <= bound:
            raise ValueError("Invalid library file size: " + name)
    metadata = json.loads(Path(config["application_map"]).read_text())["metadata"]
    for name, source in (("all-rules.json", "rules"), ("catalog.json", "catalog")):
        raw = Path(config[source]).read_bytes()
        expected = metadata["source_files"][name]
        if len(raw) != expected["bytes"] or hashlib.sha256(raw).hexdigest() != expected["sha256"]:
            raise ValueError("Library/catalog/application map versions do not match")
    secure_file(config["binary"])
    if not os.access(config["binary"], os.X_OK):
        raise ValueError("Classifier is not executable")


def load_catalog(path, application_map=None):
    result = {}
    for item in json.loads(Path(path).read_text())["entries"]:
        raw = item.get("app_id", "")
        if item.get("entry_kind") != "application_id" or not isinstance(raw, str) or not raw.isdigit():
            continue
        appid = int(raw)
        if not 1 <= appid <= 0xffffffff:
            continue
        translations = [t for t in item.get("translations", []) if isinstance(t, str)]
        result[appid] = {"appid": appid, "name": str(item["application"]), "translations": translations}
    if application_map is not None:
        seen = set()
        for item in json.loads(Path(application_map).read_text())["applications"]:
            appid = int(item["app_id"])
            if appid in seen:
                raise ValueError("Duplicate AppID in application map")
            seen.add(appid)
            if appid not in result:
                continue
            category = item.get("category_path", [])
            if not isinstance(category, list) or not all(isinstance(x, str) for x in category):
                raise ValueError("Invalid category path")
            entry = result[appid]
            entry["category_path"] = category
            entry["rule_count"] = integer(item["rule_count"], "rule_count", 0, 1_000_000)
            entry["endpoint_counts"] = {}
            preview_bytes = 0
            for field in ("domains", "domain_patterns", "ips", "cidrs"):
                values = item.get(field, [])
                if not isinstance(values, list) or not all(isinstance(x, str) and len(x) <= 4096 for x in values):
                    raise ValueError("Invalid application endpoint metadata")
                entry[field] = []
                for text in values[:16]:
                    encoded = len(text.encode("utf-8"))
                    if preview_bytes + encoded <= 4096:
                        entry[field].append(text)
                        preview_bytes += encoded
                entry["endpoint_counts"][field] = len(values)
            entry["_search"] = " ".join(category + [x for field in ("domains", "ips", "cidrs") for x in item.get(field, [])]).casefold()
        if not set(result) <= seen:
            raise ValueError("Application map does not cover the complete catalog")
    if not result:
        raise ValueError("Application catalog is empty")
    return result


def namespace_prefix(config):
    return ["/usr/sbin/ip", "netns", "exec", config["netns"]] if config["mode"] == "lab" else []


class ProcessRuntime:
    """Owns one pipeline; never resets BPF routes or native NAT connections."""
    def __init__(self, config):
        if sys.platform != "linux" or os.geteuid() != 0:
            raise ValueError("Actual routing requires root on Linux; use preview on macOS")
        self.config = config
        self.process = self.log = None
        self.cache, self.cache_until = None, 0

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def inspect(self, force=False, policy=None, deadline=None):
        time_limit(deadline, 20)
        if policy is None and not force and self.cache is not None and time.monotonic() < self.cache_until:
            return copy.deepcopy(self.cache)
        command = namespace_prefix(self.config) + [sys.executable, str(Path(__file__).resolve()),
            "runtime", "--config", self.config["_config_path"]]
        if policy is not None:
            command += ["--policy", str(policy)]
        result = subprocess.run(command, capture_output=True, text=True,
            timeout=time_limit(deadline, 20), env=SAFE_ENV)
        if result.returncode:
            raise RuntimeError((result.stderr.strip() or result.stdout.strip() or "Lab namespace is unavailable")[-1000:])
        value = json.loads(result.stdout)
        if policy is None:
            self.cache, self.cache_until = value, time.monotonic() + 3
        return value

    def start(self, policy, initialize, deadline=None):
        time_limit(deadline, 1)
        if self.alive():
            raise RuntimeError("A managed producer is already running")
        self.stop(deadline=deadline)
        time_limit(deadline, 1)
        log_path = Path(self.config["state_dir"]) / "pipeline.log"
        if log_path.exists() and log_path.stat().st_size > 1 << 20:
            os.replace(log_path, log_path.with_suffix(".previous.log"))
        self.log = open(log_path, "ab", buffering=0)
        command = namespace_prefix(self.config) + [sys.executable, str(BASE / "service_runner.py"),
            "--policy", str(policy), "--rules", self.config["rules"], "--binary", self.config["binary"],
            "--interface", self.config["interface"], "--pin-root", self.config["pin_root"],
            "--max-flows", str(self.config.get("max_flows", 4096)),
            "--initialize-quiescent" if initialize else "--resume", "--apply"]
        try:
            time_limit(deadline, 1)
            self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=self.log, start_new_session=True, env=SAFE_ENV)
        except BaseException:
            self.log.close()
            self.log = None
            raise
        self.cache_until = 0

    def wait_ready(self, timeout=20, deadline=None):
        deadline = min(deadline, time.monotonic() + timeout) if deadline is not None else time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.alive():
                raise RuntimeError("Classifier/controller pipeline exited before becoming ready")
            state = self.inspect(force=True, deadline=deadline)
            if state["runtime"]["admission_live"] and self.alive():
                return state
            time.sleep(time_limit(deadline, .25))
        raise OperationDeadline("Producer did not establish a live BPF admission lease within the time budget")

    def stop(self, deadline=None):
        deadline = deadline if deadline is not None else time.monotonic() + WORK_SECONDS
        forced = False
        if self.process is not None:
            if self.process.poll() is None:
                time_limit(deadline, 1)
                self.process.terminate()
                # Reserve enough time for forced reaping and the five-second
                # admission lease; do not spend the whole request waiting.
                grace = max(0, time_limit(deadline, 52.5) - 10.5)
                try:
                    if not grace:
                        raise subprocess.TimeoutExpired("graceful shutdown budget", grace)
                    self.process.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    forced = True
                    time_limit(deadline, 1)
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=time_limit(deadline, 5))
            else:
                self.process.wait(timeout=time_limit(deadline, 1))
            self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None
        if forced:
            if time_limit(deadline, 5.1) < 5.1:
                raise OperationDeadline("Producer was killed but its admission lease expiry could not yet be verified")
            time.sleep(5.1)
        self.cache_until = 0


class Control:
    def __init__(self, config, runtime=None):
        self.config = config
        self.mode = config["mode"]
        self.catalog = load_catalog(config["catalog"], config.get("application_map"))
        self.lines = {line["id"]: line for line in config["lines"]}
        self.lock = threading.RLock()
        self.runtime = (runtime if runtime is not None else ProcessRuntime(config)) if self.mode in ("lab", "live") else None
        if self.mode not in ("preview", "lab", "live"):
            raise ValueError("Unsupported control mode")
        self.directory = Path(config["state_dir"])
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("State directory must be owned by this user with mode 0700")
        self.state_path = self.directory / "state.json"
        self.record = {"revision": 0, "rules": [], "last_applied_revision": None, "simulated_revision": None}
        if self.state_path.exists():
            saved = json.loads(secure_file(self.state_path, private=True).read_text())
            exact_fields(saved, self.record)
            integer(saved["revision"], "stored revision")
            self.validate_rules(saved["rules"])
            for name in ("last_applied_revision", "simulated_revision"):
                if saved[name] is not None:
                    integer(saved[name], name, 0, saved["revision"])
            self.record = saved
        self.live_revision = None
        self.error = None
        self.closed = False
        self.runtime_unverified = False

    def ensure_open(self, recovery=False):
        if self.closed:
            raise ControlError("Control service is shutting down", 503, "shutting_down")
        if self.runtime_unverified and not recovery:
            raise ControlError("Previous runtime shutdown is unverified; use Stop to verify it before further changes",
                503, "runtime_unverified")

    @contextlib.contextmanager
    def mutation(self, recovery=False):
        # Never leave a write queued behind a slow apply after its HTTP client
        # timed out. The caller must explicitly retry using a fresh revision.
        if not self.lock.acquire(blocking=False):
            raise ControlError("Another control operation is in progress; refresh and retry", 409, "operation_busy")
        try:
            self.ensure_open(recovery)
            yield
        finally:
            self.lock.release()

    def validate_rules(self, rules):
        if not isinstance(rules, list) or len(rules) > MAX_RULES:
            raise ControlError("rules must be a list of at most 4096 application mappings")
        found, result = set(), []
        for rule in rules:
            exact_fields(rule, ("appid", "line_id", "learn_endpoint", "allow_udp_endpoint_hints"))
            appid = integer(rule["appid"], "appid", 1, 0xffffffff)
            if appid not in self.catalog or appid in found:
                raise ControlError("Unknown or duplicate AppID")
            if not isinstance(rule["line_id"], str) or rule["line_id"] not in self.lines:
                raise ControlError("Unknown line; only configured Telecom/Unicom lines are selectable")
            if type(rule["learn_endpoint"]) is not bool or type(rule["allow_udp_endpoint_hints"]) is not bool:
                raise ControlError("Endpoint-learning permissions must be explicit booleans")
            if rule["allow_udp_endpoint_hints"] and not rule["learn_endpoint"]:
                raise ControlError("UDP endpoint hints require endpoint learning to be enabled")
            found.add(appid)
            result.append(dict(rule))
        return sorted(result, key=lambda x: x["appid"])

    def search(self, query="", offset=0, limit=100):
        if not isinstance(query, str) or len(query) > 256:
            raise ControlError("Search query is too long")
        integer(offset, "offset", 0, 1_000_000)
        integer(limit, "limit", 1, 100)
        q = query.casefold()
        rows = [x for x in self.catalog.values() if q in (str(x["appid"]) + " " + x["name"] + " " + " ".join(x["translations"]) + " " + x.get("_search", "")).casefold()]
        rows.sort(key=lambda x: x["appid"])
        return {"items": [{k: copy.deepcopy(v) for k, v in row.items() if not k.startswith("_")} for row in rows[offset:offset + limit]], "total": len(rows), "offset": offset, "limit": limit}

    def policy(self):
        return {"schema_version": 1, "clients": self.config["clients"], "hint_ttl_seconds": 30,
            "applications": {str(rule["appid"]): {"approved": True,
                "flow_id": self.lines[rule["line_id"]]["flow_id"],
                "wan_ifname": self.lines[rule["line_id"]]["wan_ifname"],
                "learn_endpoint": rule["learn_endpoint"],
                "allow_udp_endpoint_hints": rule["allow_udp_endpoint_hints"]} for rule in self.record["rules"]},
            "static_endpoints": []}

    def status(self, deadline=None):
        with self.lock:
            lines = [{**x, "ready": False} for x in self.lines.values()]
            active, raw = None, None
            state = "stopped"
            message = "Rules are saved locally; no routing producer is running."
            simulated = self.record["simulated_revision"] if self.mode == "preview" else None
            if self.mode == "preview":
                state = "running" if simulated is not None else "stopped"
                message = "Offline simulation only. No packets, BPF maps, interfaces or system services are modified."
                for line in lines:
                    line["reason"] = "Preview has no real WAN readiness check"
            else:
                try:
                    current = self.runtime.inspect(deadline=deadline)
                    raw, readiness = current["runtime"], {x["id"]: x for x in current["lines"]}
                    lines = [{**x, **{k: v for k, v in readiness.get(x["id"], {}).items() if k in ("ready", "reason")}} for x in lines]
                    if self.runtime.alive() and raw["admission_live"] and self.live_revision is not None:
                        state, active = "running", self.live_revision
                        message = "Managed classifier and BPF admission are live; existing connections retain their selected exit."
                    elif self.runtime.alive():
                        state, message = "error", "Producer exists but its BPF admission lease is not live."
                    elif self.live_revision is not None:
                        state, message = "error", "Managed pipeline stopped unexpectedly; saved rules are not currently active."
                    elif raw["admission_live"]:
                        state, message = "unavailable", "Another producer has a live lease; this controller does not own it."
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError) as exc:
                    state, message = "unavailable", "Configured routing runtime is unavailable: " + str(exc)[:600]
                    for line in lines:
                        line["reason"] = message
                if self.error:
                    state, message = "error", self.error
                if self.runtime_unverified:
                    active = None
            return {"mode": self.mode, "simulated": self.mode == "preview", "state": state, "message": message,
                "runtime_unverified": self.runtime_unverified,
                "saved_revision": self.record["revision"], "active_revision": active,
                "simulated_revision": simulated, "last_applied_revision": self.record["last_applied_revision"],
                "catalog_total": len(self.catalog), "clients": list(self.config["clients"]), "lines": lines,
                "policy": {"revision": self.record["revision"], "rules": copy.deepcopy(self.record["rules"])}, "runtime": raw}

    def save(self, body):
        exact_fields(body, ("expected_revision", "rules"))
        integer(body["expected_revision"], "expected_revision")
        rules = self.validate_rules(body["rules"])
        with self.mutation():
            if body["expected_revision"] != self.record["revision"]:
                raise ControlError("Policy changed; refresh before saving", 409, "revision_conflict")
            next_record = {**self.record, "revision": self.record["revision"] + 1, "rules": rules}
            atomic_json(self.state_path, next_record)
            self.record = next_record
            return self.status()

    def apply(self, body, deadline=None):
        exact_fields(body, ("revision", "initial_quiescent"))
        integer(body["revision"], "revision")
        if type(body["initial_quiescent"]) is not bool:
            raise ControlError("initial_quiescent must be an explicit boolean")
        with self.mutation():
            time_limit(deadline, 1)
            if body["revision"] != self.record["revision"]:
                raise ControlError("Saved revision changed; refresh before applying", 409, "revision_conflict")
            if self.mode == "preview":
                next_record = {**self.record, "simulated_revision": body["revision"]}
                atomic_json(self.state_path, next_record)
                self.record, self.error = next_record, None
                return self.status()
            started = time.monotonic()
            deadline = min(deadline, started + APPLY_SECONDS) if deadline is not None else started + APPLY_SECONDS
            work_deadline = deadline - (APPLY_SECONDS - WORK_SECONDS)
            policy_path = self.directory / ("policy-%d.json" % body["revision"])
            atomic_json(policy_path, self.policy())
            # All checks precede stopping the old producer. Preflight failure
            # therefore keeps both its old policy and existing sessions intact.
            try:
                current = self.runtime.inspect(force=True, policy=policy_path, deadline=work_deadline)
                raw = current["runtime"]
                needed = {x["line_id"] for x in self.record["rules"]}
                ready = {x["id"] for x in current["lines"] if x["ready"]}
                if not needed <= ready:
                    raise ControlError("A selected line has no verified Flow/WAN/NAT target", 409, "line_unavailable")
                if raw["admission_live"] and not self.runtime.alive():
                    raise ControlError("Another producer owns a live lease", 409, "producer_conflict")
                if not raw["armed"] and not body["initial_quiescent"]:
                    raise ControlError("Initial arm requires the explicit idle-client assertion", 409, "quiescence_required")
            except ControlError:
                raise
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError) as exc:
                raise ControlError("Preflight failed; current policy was retained: " + str(exc)[:600], 503, "preflight_failed") from exc
            try:
                time_limit(work_deadline, 1)
                self.runtime.stop(deadline=work_deadline)
                self.live_revision = None
                after = self.runtime.inspect(force=True, deadline=work_deadline)["runtime"]
                if after["admission_live"]:
                    raise RuntimeError("Previous producer lease is still live; no replacement was started")
                time_limit(work_deadline, 1)
                self.runtime.start(policy_path, initialize=not after["armed"], deadline=work_deadline)
                self.runtime.wait_ready(deadline=work_deadline)
                time_limit(work_deadline, 1)
                next_record = {**self.record, "last_applied_revision": body["revision"]}
                atomic_json(self.state_path, next_record)
                self.record, self.live_revision, self.error = next_record, body["revision"], None
                return self.status(deadline=deadline)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError) as exc:
                self.live_revision = None
                try:
                    self.runtime.stop(deadline=deadline)
                    stopped = self.runtime.inspect(force=True, deadline=deadline)["runtime"]
                    if self.runtime.alive() or stopped["admission_live"]:
                        raise RuntimeError("Producer or admission lease is still live")
                    self.error = "Apply failed; replacement producer is stopped and no new policy is active. Existing pinned connections are retained. " + str(exc)[:500]
                    error_id = "apply_failed"
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError) as cleanup:
                    self.runtime_unverified = True
                    self.error = "Apply did not commit. Runtime shutdown could not be verified within the request budget; further changes are blocked until Stop verifies it. " + str(cleanup)[:500]
                    error_id = "runtime_unverified"
                raise ControlError(self.error, 503, error_id) from exc

    def stop(self, body, deadline=None):
        exact_fields(body, ())
        with self.mutation(recovery=True):
            time_limit(deadline, 1)
            if self.mode == "preview":
                next_record = {**self.record, "simulated_revision": None}
                atomic_json(self.state_path, next_record)
                self.record, self.error = next_record, None
                return self.status()
            try:
                now = time.monotonic()
                deadline = min(deadline, now + APPLY_SECONDS) if deadline is not None else now + APPLY_SECONDS
                work_deadline = deadline - (APPLY_SECONDS - WORK_SECONDS)
                before = self.runtime.inspect(force=True, deadline=work_deadline)["runtime"]
                if before["admission_live"] and not self.runtime.alive():
                    raise ControlError("Cannot stop a producer not owned by this controller", 409, "producer_conflict")
                self.runtime.stop(deadline=work_deadline)
                self.live_revision = None
                after = self.runtime.inspect(force=True, deadline=deadline)["runtime"]
                if after["admission_live"]:
                    raise RuntimeError("Producer stopped, but admission lease has not yet expired")
                self.error, self.runtime_unverified = None, False
                return self.status(deadline=deadline)
            except ControlError:
                raise
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError) as exc:
                self.runtime_unverified = True
                self.error = "Could not verify admission drain: " + str(exc)[:600]
                raise ControlError(self.error, 503, "stop_unverified") from exc

    def close(self):
        with self.lock:
            self.closed = True
            if self.runtime is not None:
                self.runtime.stop(deadline=time.monotonic() + APPLY_SECONDS)


def validate_lan_program(config, backend):
    """The selected LAN must actually run the program using these exact maps."""
    filters = subprocess.run(["/usr/sbin/tc", "-j", "filter", "show", "dev", config["interface"], "ingress"],
        capture_output=True, text=True, check=True, timeout=5, env=SAFE_ENV)
    required = set()
    for name in ("dpi_rt_cfg_v1", "dpi_rt_cli_v1", "dpi_rt_flow_v1", "dpi_rt_hint_v1"):
        info = backend.command("map", "show", "pinned", str(Path(config["pin_root"]) / name))
        if isinstance(info, list):
            info = info[0] if len(info) == 1 else {}
        required.add(integer(info["id"], "kernel map id", 1, 2**32 - 1))
    for entry in json.loads(filters.stdout):
        program = entry.get("options", {}).get("id") if entry.get("kind") == "bpf" else None
        if type(program) is not int:
            continue
        info = backend.command("prog", "show", "id", str(program))
        if isinstance(info, list):
            info = info[0] if len(info) == 1 else {}
        if required <= set(info.get("map_ids", [])):
            return
    raise ValueError("Configured LAN has no attached patched Landscape program using these maps")


def runtime_inspect(config, policy_path=None):
    """Read kernel state only after immutable deployment/namespace checks."""
    if config["mode"] not in ("lab", "live") or sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("Runtime inspection requires a configured Linux root deployment")
    if config["mode"] == "lab":
        target = Path("/run/netns") / config["netns"]
        if not target.exists() or os.stat(target).st_ino != os.stat("/proc/self/ns/net").st_ino:
            raise ValueError("Refusing runtime access outside the configured network namespace")
        links = subprocess.run(["/usr/sbin/ip", "-j", "link", "show"], capture_output=True, text=True, check=True, timeout=5, env=SAFE_ENV)
        names = {x["ifname"] for x in json.loads(links.stdout)}
        if names != {"lo", "lan0", "client0", "wan1", "peer1", "wan2", "peer2"}:
            raise ValueError("Lab interfaces differ from the isolated fixture; refusing management interfaces")
        default = subprocess.run(["/usr/sbin/ip", "route", "show", "default"], capture_output=True, text=True, check=True, timeout=5, env=SAFE_ENV)
        if default.stdout.strip():
            raise ValueError("Lab must not have a default route")
    else:
        links = subprocess.run(["/usr/sbin/ip", "-j", "link", "show"], capture_output=True, text=True, check=True, timeout=5, env=SAFE_ENV)
        names = {x["ifname"] for x in json.loads(links.stdout)}
        required = {config["interface"], *(x["wan_ifname"] for x in config["lines"])}
        if not required <= names:
            raise ValueError("Configured LAN/WAN interfaces are not present")
        if Path(config["pin_root"]).resolve() != Path(config["pin_root"]):
            raise ValueError("Pinned map root cannot use symlink aliases")
    spec = importlib.util.spec_from_file_location("web_control_router", BASE / "router.py")
    router = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(router)
    def bounded_run(*args, **kwargs):
        return subprocess.run(*args, **kwargs, timeout=5, env=SAFE_ENV)
    backend = router.RoutingBackend(config["pin_root"], executable="/usr/sbin/bpftool", runner=bounded_run)
    backend.check_routes()
    if config["mode"] == "live":
        validate_lan_program(config, backend)
    state = backend.status()
    lines = []
    for line in config["lines"]:
        try:
            backend.check_wan(line, 4)
            lines.append({"id": line["id"], "ready": True})
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            lines.append({"id": line["id"], "ready": False, "reason": str(exc)[:300]})
    if policy_path is not None:
        policy_path = absolute(str(policy_path), "policy")
        if policy_path.parent.resolve() != Path(config["state_dir"]).resolve() or not re.fullmatch(r"policy-\d+\.json", policy_path.name):
            raise ValueError("Policy is outside the controller state directory")
        policy = router.policy_load(secure_file(policy_path, private=True))
        if policy["clients"] != config["clients"]:
            raise ValueError("Client scope differs from immutable deployment configuration")
        for app in policy["applications"].values():
            backend.check_wan(app, 4)
    # Bound browser response size; the count remains the complete dump count.
    state["pinned_connection_count"] = len(state["pinned_connections"])
    state["pinned_connections"] = state["pinned_connections"][:200]
    return {"runtime": state, "lines": lines}


class Handler(BaseHTTPRequestHandler):
    server_version = "LandscapeDPI/1"
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_):
        pass  # Never log authorization headers or submitted request bodies.

    def respond(self, status, payload):
        data = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(data)

    def authorize(self):
        values = self.headers.get_all("Authorization", [])
        expected = "Bearer " + self.server.control_token
        if len(values) != 1 or not hmac.compare_digest(values[0].encode(), expected.encode()):
            raise ControlError("Authentication required", 401, "unauthorized")
        hosts = self.headers.get_all("Host", [])
        allowed = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
        if len(hosts) != 1 or hosts[0] not in allowed:
            raise ControlError("Invalid loopback Host header", 403, "host_rejected")
        origins = self.headers.get_all("Origin", [])
        if len(origins) > 1:
            raise ControlError("Origin rejected", 403, "origin_rejected")
        if origins:
            parsed = urlsplit(origins[0])
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ControlError("Origin rejected", 403, "origin_rejected")
            if parsed.scheme not in ("http", "https") or parsed.hostname not in ("localhost", "127.0.0.1") or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
                raise ControlError("Origin rejected", 403, "origin_rejected")

    def body(self):
        if self.headers.get_all("Transfer-Encoding", []):
            raise ControlError("Transfer-Encoding is unsupported")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not re.fullmatch(r"\d{1,10}", lengths[0]):
            raise ControlError("A single Content-Length is required")
        length = int(lengths[0])
        if not 0 < length <= MAX_BODY:
            raise ControlError("JSON body exceeds the 1 MiB limit", 413, "body_too_large")
        types = self.headers.get_all("Content-Type", [])
        if len(types) != 1 or types[0].split(";", 1)[0].strip().lower() != "application/json":
            raise ControlError("Content-Type must be application/json", 415, "content_type")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ControlError("Truncated JSON request")
        try:
            def reject_constant(_):
                raise ValueError("Non-finite JSON number")
            def unique_object(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("Duplicate JSON key")
                    result[key] = value
                return result
            return json.loads(raw, parse_constant=reject_constant, object_pairs_hook=unique_object)
        except (ValueError, UnicodeError) as exc:
            raise ControlError("Malformed JSON request") from exc

    def dispatch(self):
        request_deadline = time.monotonic() + APPLY_SECONDS
        try:
            self.authorize()
            parsed = urlsplit(self.path)
            if parsed.scheme or parsed.netloc or parsed.fragment:
                raise ControlError("Relative endpoint path required")
            path = parsed.path
            control = self.server.control
            if self.command == "GET" and path == "/catalog":
                query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
                if set(query) - {"q", "offset", "limit"} or any(len(x) != 1 for x in query.values()):
                    raise ControlError("Unexpected catalog query")
                offset, limit = query.get("offset", ["0"])[0], query.get("limit", ["100"])[0]
                if not re.fullmatch(r"\d{1,7}", offset) or not re.fullmatch(r"\d{1,3}", limit):
                    raise ControlError("Invalid catalog pagination")
                result = control.search(query.get("q", [""])[0], int(offset), int(limit))
            elif parsed.query:
                raise ControlError("This endpoint does not accept a query")
            elif self.command == "GET" and path == "/status":
                result = control.status()
            elif self.command == "PUT" and path == "/policy":
                result = control.save(self.body())
            elif self.command == "POST" and path == "/apply":
                result = control.apply(self.body(), deadline=request_deadline)
            elif self.command == "POST" and path == "/stop":
                result = control.stop(self.body(), deadline=request_deadline)
            else:
                raise ControlError("Unknown endpoint or method", 404, "not_found")
            self.respond(200, {"data": result})
        except ControlError as exc:
            self.respond(exc.status, {"message": str(exc), "error_id": exc.error_id})
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            self.respond(400, {"message": "Invalid request data", "error_id": "invalid_request"})
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            self.respond(503, {"message": "Control service could not complete the operation", "error_id": "service_unavailable"})

    do_GET = do_PUT = do_POST = do_DELETE = do_PATCH = do_OPTIONS = dispatch


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, control, token):
        if address[0] != "127.0.0.1":
            raise ValueError("Control API must bind IPv4 loopback only")
        if not isinstance(token, str) or not 32 <= len(token) <= 256 or not re.fullmatch(r"[A-Za-z0-9_-]+", token):
            raise ValueError("A private random URL-safe control token of at least 32 characters is required")
        self.control, self.control_token = control, token
        super().__init__(address, Handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("serve", "runtime"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--policy", type=Path)
    args = parser.parse_args(argv)
    config = load_config(args.config)
    if args.command == "runtime":
        print(json.dumps(runtime_inspect(config, args.policy)))
        return 0
    if args.policy is not None:
        parser.error("--policy is only valid for the internal runtime inspector")
    token = secure_file(config["token_file"], private=True).read_text().strip()
    control = Control(config)
    server = Server(("127.0.0.1", PORT), control, token)
    stopping = threading.Event()
    def stop(_sig, _frame):
        if not stopping.is_set():
            stopping.set()
            threading.Thread(target=server.shutdown, daemon=True).start()
    previous = {s: signal.signal(s, stop) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        server.serve_forever(poll_interval=.2)
    finally:
        server.server_close()
        control.close()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, ControlError, subprocess.SubprocessError) as exc:
        print(json.dumps({"message": str(exc), "error_id": "startup_failed"}), file=sys.stderr)
        raise SystemExit(2)
