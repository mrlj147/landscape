#!/usr/bin/env python3
"""Prepare an offline installation tree. Never execute/install services or network commands."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import shutil
import stat

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("staging_control", BASE / "adapters/landscape/web_control.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def stage(args):
    # Destination must be new: do not overwrite an installed or existing household configuration.
    if args.output.exists():
        raise ValueError("Output directory already exists")
    lan = args.lan
    if not m.re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", lan) or lan in ("any", "lo", args.telecom_wan, args.unicom_wan):
        raise ValueError("Explicit distinct LAN/WAN names required")
    binary = args.binary.resolve()
    header = binary.read_bytes()[:20]
    if len(header) < 20 or header[:5] != b"\x7fELF\x02" or header[5] != 1 or int.from_bytes(header[18:20], "little") not in (62, 183):
        raise ValueError("Use a built Linux x86_64/aarch64 ELF classifier; a macOS build cannot run on Linux")
    source = args.library.resolve()
    config = {"schema_version": 1, "mode": "live", "state_dir": "/var/lib/landscape-dpi/state", "token_file": "/var/lib/landscape-dpi/control.token", "catalog": "/var/lib/landscape-dpi/library/catalog.json", "application_map": "/var/lib/landscape-dpi/library/applications.json", "rules": "/var/lib/landscape-dpi/library/all-rules.json", "binary": "/opt/landscape-dpi/bin/dpi-bridge", "clients": args.client, "interface": lan, "pin_root": args.pin_root, "lines": [{"id": "telecom", "name": "电信", "flow_id": args.telecom_flow, "wan_ifname": args.telecom_wan}, {"id": "unicom", "name": "联通", "flow_id": args.unicom_flow, "wan_ifname": args.unicom_wan}]}
    mapping = json.loads((source / "applications.json").read_text())
    for name in ("all-rules.json", "catalog.json"):
        raw = (source / name).read_bytes(); wanted = mapping["metadata"]["source_files"][name]
        if len(raw) != wanted["bytes"] or hashlib.sha256(raw).hexdigest() != wanted["sha256"]:
            raise ValueError("Rules, catalog and application mapping are not the same version")
    m.load_catalog(source / "catalog.json", source / "applications.json")
    root = args.output.resolve(); root.mkdir(parents=True, mode=0o700)
    runtime = root / "opt/landscape-dpi/adapters/landscape"; runtime.mkdir(parents=True)
    for name in ("receiver.py", "router.py", "service_runner.py", "web_control.py"):
        shutil.copyfile(BASE / "adapters/landscape" / name, runtime / name)
    dest = root / "opt/landscape-dpi/bin/dpi-bridge"; dest.parent.mkdir(); shutil.copyfile(binary, dest); dest.chmod(0o700)
    library = root / "var/lib/landscape-dpi/library"; library.mkdir(parents=True, mode=0o700)
    for name in ("all-rules.json", "catalog.json", "applications.json"):
        shutil.copyfile(source / name, library / name); (library / name).chmod(0o600)
    token = root / "var/lib/landscape-dpi/control.token"; token.write_text(secrets.token_urlsafe(48) + "\n"); token.chmod(0o600)
    cfg = root / "etc/landscape-dpi/control.json"; cfg.parent.mkdir(parents=True, mode=0o700); cfg.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n"); cfg.chmod(0o600)
    unit = root / "etc/systemd/system/landscape-dpi.service"; unit.parent.mkdir(parents=True); shutil.copyfile(BASE / "deployment/landscape-dpi.service", unit)
    # Validate all non-runtime configuration fields using staged local files.
    local = dict(config)
    for field in ("state_dir", "token_file", "catalog", "application_map", "rules", "binary"):
        local[field] = str(root / config[field].lstrip("/"))
    check = root / ".check.json"; check.write_text(json.dumps(local)); check.chmod(0o600)
    try:
        m.load_config(check)
    finally:
        check.unlink()
    manifest = {"schema_version": 1, "landscape_base": "v0.27.1", "files": {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob("*")) if p.is_file()}, "services_started": False, "network_modified": False}
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--library", type=Path, required=True, help="Private same-version all-rules.json, catalog.json, applications.json")
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--client", action="append", required=True)
    p.add_argument("--lan", required=True)
    p.add_argument("--pin-root", required=True)
    p.add_argument("--telecom-flow", type=int, required=True)
    p.add_argument("--telecom-wan", required=True)
    p.add_argument("--unicom-flow", type=int, required=True)
    p.add_argument("--unicom-wan", required=True)
    result = stage(p.parse_args())
    print(json.dumps({"files": len(result["files"]), "services_started": False, "network_modified": False}))

if __name__ == "__main__":
    main()
