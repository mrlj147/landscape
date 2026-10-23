#!/usr/bin/env python3
"""Supervise LAN capture -> full classifier -> controlled Landscape admission.

Default prints the exact process plan. --apply requires a patched, already
configured Landscape and explicit quiescent initialization or safe resume.
Stopping closes capture first, allowing the adapter to drain at EOF. A killed
adapter loses its five-second admission lease; pinned connections remain.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("landscape_service_router", BASE / "router.py")
router = importlib.util.module_from_spec(spec)
spec.loader.exec_module(router)


def commands(args):
    policy = router.policy_load(args.policy)
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", args.interface):
        raise ValueError("Expected one explicit Linux LAN interface name")
    if args.interface == "any":
        raise ValueError("Capture requires an Ethernet LAN device, not Linux cooked capture on any")
    if not args.rules.is_file() or not 0 < args.rules.stat().st_size <= 64 << 20:
        raise ValueError("Complete rules JSON is missing or oversized")
    binary = Path(args.binary)
    if not binary.is_absolute() or not os.access(binary, os.X_OK):
        raise ValueError("Classifier must be an executable at an absolute path")
    if not Path(args.pin_root).is_absolute():
        raise ValueError("An absolute existing Landscape map namespace is required")
    if args.initialize_quiescent == args.resume:
        raise ValueError("Choose exactly one of --initialize-quiescent or --resume")
    clients = policy["clients"]
    capture_filter = "(tcp or udp) and (" + " or ".join("host " + c for c in clients) + ")"
    return [
        ["tcpdump", "-i", args.interface, "-p", "-nn", "-s", "0", "-U", "-w", "-", capture_filter],
        [str(binary), "replay", "--rules", str(args.rules.resolve()), "--all", "--pcap", "-",
         "--client-cidr", ",".join(c + "/32" for c in clients), "--max-flows", str(args.max_flows)],
        [sys.executable, str(BASE / "router.py"), "--policy", str(args.policy.resolve()), "--apply", "--quiet",
         "--pin-root", args.pin_root, "--initialize-quiescent" if args.initialize_quiescent else "--resume"],
    ]


def supervise(plan, stopping, popen=subprocess.Popen, sleep=time.sleep):
    children = []
    try:
        capture = popen(plan[0], stdout=subprocess.PIPE)
        children.append(capture)
        try:
            classifier = popen(plan[1], stdin=capture.stdout, stdout=subprocess.PIPE)
            children.append(classifier)
        finally:
            capture.stdout.close()
        try:
            receiver = popen(plan[2], stdin=classifier.stdout)
            children.append(receiver)
        finally:
            classifier.stdout.close()
        while not stopping() and all(child.poll() is None for child in children):
            sleep(0.2)
        # Live capture EOF is also a failure unless the operator requested stop.
        return 0 if stopping() else 2
    finally:
        # Capture EOF propagates through the classifier so router.py executes
        # its drain finally block. Never reset route or native NAT maps here.
        errors = []
        if children and children[0].poll() is None:
            try:
                children[0].terminate()
            except ProcessLookupError:
                pass
            except OSError as exc:
                errors.append(str(exc))
        for child in children:
            try:
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.terminate()
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=3)
            except ProcessLookupError:
                pass
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(str(exc))
        if errors:
            raise RuntimeError("Could not reap every pipeline process: " + "; ".join(errors))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--pin-root", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--initialize-quiescent", action="store_true")
    mode.add_argument("--resume", action="store_true")
    parser.add_argument("--max-flows", type=int, default=4096)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    if not 1 <= args.max_flows <= 65536:
        parser.error("--max-flows must be between 1 and 65536")
    plan = commands(args)
    if not args.apply:
        print(json.dumps({"status": "planned", "commands": plan, "network_action": "none"}))
        return 0
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("--apply requires root on the isolated or explicitly configured Linux router")
    stop = False

    def stop_requested(_signum, _frame):
        nonlocal stop
        stop = True

    previous = {s: signal.signal(s, stop_requested) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        return supervise(plan, lambda: stop)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        raise SystemExit(2)
