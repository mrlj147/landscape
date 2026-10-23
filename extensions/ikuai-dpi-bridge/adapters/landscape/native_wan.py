"""Read Landscape v0.27.1 WAN/Flow metadata without changing its database.

Only public routing metadata is selected. PPP credentials are never selected,
returned, or copied into the application controller's state.
"""
import json
from pathlib import Path
import sqlite3
import uuid


def link_id(value):
    return str(uuid.UUID(bytes=value) if isinstance(value, bytes) else uuid.UUID(str(value)))


def discover(database):
    path = Path(database)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Landscape database must be an absolute local path")
    # mode=ro never creates a missing database. Do not use immutable=1: it
    # would ignore the native writer's current WAL and return stale WANs.
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        wans = db.execute("""SELECT id, name, attach_iface_name,
            json_extract(kind, '$.t'), json_extract(kind, '$.ppp_iface_name'),
            json_extract(v4, '$.enable'), json_extract(nat, '$.enable')
            FROM wan_links ORDER BY link_chain_id, id""").fetchall()
        flows = db.execute("""SELECT flow_id, packet_handle_iface_name
            FROM flow_configs WHERE enable=1 ORDER BY flow_id""").fetchall()
    finally:
        db.close()
    if len(wans) > 1023:
        raise ValueError("WAN count exceeds Landscape's native chain capacity")
    candidates = {}
    used = set()
    for flow, raw in flows:
        if type(flow) is not int or not 1 <= flow <= 255:
            continue
        if flow in used:
            raise ValueError("Duplicate native Flow ID")
        used.add(flow)
        entries = json.loads(raw)
        if not isinstance(entries, list):
            raise ValueError("Invalid native Flow targets")
        targets = set()
        for entry in entries:
            if not isinstance(entry, dict) or type(entry.get("weight", 1)) is not int:
                raise ValueError("Invalid native Flow target weight")
            if entry.get("weight", 1) <= 0:
                continue
            target = entry.get("target", {})
            if target.get("t") != "interface":
                targets.add(None)
            else:
                targets.add(link_id(target["link_id"]))
        if len(targets) == 1 and None not in targets:
            candidates.setdefault(next(iter(targets)), []).append(flow)
    result = []
    for ident, name, attach, kind, ppp, enabled, nat in wans:
        ident = link_id(ident)
        interface = ppp if kind == "pppd" else attach
        if not isinstance(interface, str) or not isinstance(name, str):
            raise ValueError("Invalid native WAN metadata")
        if any(value is not None and (type(value) is not int or value not in (0, 1)) for value in (enabled, nat)):
            raise ValueError("Invalid native WAN switches")
        flow = min(candidates.get(ident, []), default=None)
        reason = None
        if not enabled:
            reason = "此 WAN 尚未启用 IPv4"
        elif not nat:
            reason = "此 WAN 尚未启用 NAT"
        elif flow is None:
            reason = "尚无仅指向此 WAN 的已启用 Flow（应用分流支持 Flow ID 1–255）"
        result.append({"id": ident, "name": (name.strip() or interface)[:80],
            "flow_id": flow, "wan_ifname": interface, "enabled": bool(enabled),
            "configured_ready": reason is None, "configuration_reason": reason})
    if len({x["id"] for x in result}) != len(result):
        raise ValueError("Duplicate native WAN identity")
    return result
