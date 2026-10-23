#!/usr/bin/env python3
"""Linux-only verifier + BPF_PROG_TEST_RUN check; attaches to no network interface.

Requires root/capabilities, mounted bpffs, clang with BPF target, bpftool,
libbpf development headers and /sys/kernel/btf/vmlinux. Creates only a unique
temporary bpffs directory under /sys/fs/bpf/landscape and removes its own pins.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("landscape_receiver", BASE / "receiver.py")
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)

SOURCE = r'''
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "dpi/metadata.h"
char LICENSE[] SEC("license") = "GPL";
SEC("xdp") int dpi_smoke(struct xdp_md *ctx) {
    const unsigned char *p = (void *)(long)ctx->data;
    const void *end = (void *)(long)ctx->data_end;
    if ((const void *)(p + 14) > end) return 2;
    if (p[12] == 8 && p[13] == 0) dpi_observe_xdp(ctx, 4);
    else if (p[12] == 0x86 && p[13] == 0xdd) dpi_observe_xdp(ctx, 6);
    return 2;
}
'''


def run(*args, **kw):
    result = subprocess.run(list(args), capture_output=True, **kw)
    if result.returncode:
        error = result.stderr.decode(errors="replace") if isinstance(result.stderr, bytes) else result.stderr
        raise RuntimeError(f"{args[0]} exited {result.returncode}: {error}")
    return result


def main():
    if sys.platform != "linux":
        raise SystemExit("Linux is required; no BPF verification was performed.")
    for tool in ("clang", "bpftool"):
        if not shutil.which(tool):
            raise SystemExit(f"Missing {tool}; install Linux test dependencies first.")
    root = Path("/sys/fs/bpf/landscape")
    if not root.is_dir():
        raise SystemExit("Expected existing Landscape bpffs root; refusing to mount or initialize it.")
    pin_dir = Path(tempfile.mkdtemp(prefix="dpi_smoke_", dir=root))
    try:
        with tempfile.TemporaryDirectory(prefix="landscape-dpi-smoke-") as temp:
            temp = Path(temp)
            (temp / "vmlinux.h").write_bytes(run("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c").stdout)
            (temp / "smoke.bpf.c").write_text(SOURCE)
            run("clang", "-O2", "-g", "-target", "bpf", "-I", str(temp), "-I", str(BASE / "overlay/landscape-ebpf/src/bpf"),
                "-c", str(temp / "smoke.bpf.c"), "-o", str(temp / "smoke.bpf.o"))
            run("bpftool", "prog", "load", str(temp / "smoke.bpf.o"), str(pin_dir / "program"), "type", "xdp", "pinmaps", str(pin_dir))
            backend = r.Bpftool(pin_dir)
            # A synthetic LAN TCP packet; program test-run never transmits it.
            packet = bytearray(54); packet[:12] = bytes.fromhex("020000000001020000000002"); packet[12:14] = b"\x08\x00"
            packet[14] = 0x45; packet[16:18] = struct.pack("!H", 40); packet[22] = 64; packet[23] = 6
            packet[26:30] = bytes([10,10,10,69]); packet[30:34] = bytes([203,0,113,5])
            packet[34:38] = struct.pack("!HH", 50123, 80); packet[46] = 0x50; packet[47] = 2
            (temp / "packet.bin").write_bytes(packet)
            def test_run():
                output = run("bpftool", "-j", "prog", "run", "pinned", str(pin_dir / "program"), "data_in", str(temp / "packet.bin"),
                             "data_out", str(temp / "output.bin"), "repeat", "3", text=True)
                assert json.loads(output.stdout)["retval"] == 2
                assert (temp / "output.bin").read_bytes() == packet
            test_run(); assert backend.counters() == []
            event = {"schema_version":1,"event":"classification","appid":3001234,"rule_id":42,"observed_at":time.time(),
                     "flow":{"direction":"lan_to_wan","ip_version":4,"protocol":"tcp","src_ip":"10.10.10.69","src_port":50123,"dst_ip":"203.0.113.5","dst_port":80}}
            item = backend.install(r.plan(event)); test_run()
            counts = backend.counters(); assert len(counts)==1 and counts[0]["packets_after_label"]==3 and counts[0]["bytes_after_label"]==162
            assert counts[0]["label_metadata"]["appid"] == 3001234
            key = bytes.fromhex(item["key_hex"]); value = bytearray.fromhex(item["value_hex"]); value[:8] = struct.pack("=Q", 1)
            backend.command("map", "update", "pinned", str(pin_dir / r.LABEL_MAP), "key", "hex", *key.hex(" ").split(), "value", "hex", *value.hex(" ").split(), "exist")
            test_run(); assert backend.counters()[0]["packets_after_label"] == 3
            print(json.dumps({"status":"passed","kernel_verifier":True,"bpf_prog_test_run":True,"network_interfaces_attached":0,
                              "tests":["unlabeled-no-count","label-count","expiry-no-count","packet-unchanged"]}))
    finally:
        # Delete only pins created under this unique, empty-at-start test folder.
        for item in pin_dir.iterdir():
            item.unlink()
        pin_dir.rmdir()


if __name__ == "__main__":
    main()
