#!/usr/bin/env python3
"""Real Linux TC -> two isolated veth WANs -> native Landscape NAT4 acceptance.
Run sudo unshare --net python3 THIS --source PATCHED_LANDSCAPE --output DIR.
Refuses the host network namespace (eth0/default route present). Creates only
private veth devices and unique BPF pins. Never connects to a physical WAN.
"""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("dpi_router_test", BASE / "router.py")
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)

def run(*args, **kw):
    result = subprocess.run(list(map(str, args)), capture_output=True, **kw)
    if result.returncode:
        raise RuntimeError("Command failed: " + " ".join(map(str, args)) + "\n" +
                           result.stderr.decode(errors="replace")[-12000:])
    return result.stdout

def checksum(data):
    if len(data) % 2: data += b"\0"
    result = sum(struct.unpack("!%dH" % (len(data)//2), data))
    while result >> 16: result = (result & 65535) + (result >> 16)
    return (~result) & 65535

def packet(sport, proto=6, flags=2, seq=1000, dst="203.0.113.5", fragment=0, data=b""):
    src = socket.inet_aton("10.10.10.69"); dest = socket.inet_aton(dst)
    if proto == 6:
        payload = bytearray(struct.pack("!HHIIBBHHH", sport,80,seq,0,0x50,flags,65535,0,0))
        payload.extend(data)
        pseudo = src + dest + struct.pack("!BBH",0,6,len(payload))
        struct.pack_into("!H",payload,16,checksum(pseudo+payload))
    else:
        payload=bytearray(struct.pack("!HHHH",sport,80,12,0)+b"TEST")
    ip=bytearray(struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(payload),sport,fragment,64,proto,0,src,dest))
    struct.pack_into("!H",ip,10,checksum(ip))
    return bytes.fromhex("0200000000020200000000010800")+ip+payload

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    ap.add_argument("--events",type=Path)
    ap.add_argument("--controller-binary",type=Path)
    args=ap.parse_args()
    if os.geteuid()!=0 or os.name!="posix": raise SystemExit("Root in a fresh Linux network namespace required")
    if any(x["ifname"] != "lo" for x in json.loads(run("ip", "-j", "link", "show"))) or run("ip","route","show","default").strip():
        raise SystemExit("Refusing a namespace containing eth0 or a default route")
    for tool in ("clang","bpftool","tc","ip"):
        if not shutil.which(tool): raise SystemExit("Missing "+tool)
    args.output.mkdir(parents=True,exist_ok=False)
    bpffs=Path("/sys/fs/bpf/landscape")
    bpffs.mkdir(exist_ok=True)
    pins=Path(tempfile.mkdtemp(prefix="dpi_route_test_",dir=bpffs))
    report={"status":"running","physical_interfaces_touched":[],"tests":[],"kernel":os.uname().release}
    logs=args.output/"commands.log"
    def bpf(*argv):
        out=run("bpftool","-j",*argv)
        return json.loads(out) if out.strip() else None
    def put(map_path,key,value):
        bpf("map","update","pinned",map_path,"key","hex",*key.hex(" ").split(),"value","hex",*value.hex(" ").split(),"any")
    def dump(map_path): return bpf("map","dump","pinned",map_path)
    def key(sport,proto=6,dst="203.0.113.5"):
        return r.r.encode_flow(dict(direction="lan_to_wan",ip_version=4,protocol=proto,src_ip="10.10.10.69",src_port=sport,dst_ip=dst,dst_port=80))
    def route_value(sport,proto=6,dst="203.0.113.5"):
        for row in dump(pins/"lan_maps/dpi_rt_flow_v1"):
            if r.r.raw_bytes(row["key"])==key(sport,proto,dst): return r.r.raw_bytes(row["value"])
        return None
    interfaces=[]; sockets=[]
    try:
        build=args.output/"build"; build.mkdir()
        (build/"vmlinux.h").write_bytes(run("bpftool","btf","dump","file","/sys/kernel/btf/vmlinux","format","c"))
        bpfsource=build/"bpf-source"
        shutil.copytree(args.source/"landscape-ebpf/src/bpf",bpfsource)
        # bpftool pinmaps does not set libbpf's automatic pin-root. Disable
        # declaration-level autopinning only in this disposable test copy;
        # every map is explicitly pinned under the unique test directory.
        for header in bpfsource.rglob("*.h"):
            text=header.read_text()
            text=text.replace("__uint(pinning, LIBBPF_PIN_BY_NAME);","")
            header.write_text(text)
        def compile_object(src,obj,include_override=None):
            cmd=["clang","-O2","-g","-target","bpf","-mcpu=v2","-Wno-compare-distinct-pointer-types","-I",build]
            if include_override: cmd += ["-I",include_override]
            cmd += ["-I",bpfsource,"-c",src,"-o",obj]
            logs.write_text(logs.read_text() + " ".join(map(str,cmd))+"\n" if logs.exists() else " ".join(map(str,cmd))+"\n")
            run(*cmd)
        # Reduce only the pending-cleanup delay in the test build. Native NAT
        # lifecycle and application decision code are unchanged.
        pending=bpfsource/"dpi/tc_route.h"
        pending.write_text(pending.read_text().replace("30000000000ULL", "1000000000ULL"))
        timer=bpfsource/"dpi/routing.h"
        timer.write_text(timer.read_text().replace("30000000000ULL", "1000000000ULL"))
        route_maps=bpfsource/"dpi/routing_maps.h"
        map_text=route_maps.read_text()
        map_text=map_text.replace("__uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536);\n    __type(key, struct dpi_flow_key_v1); __type(value, struct dpi_rt_decision);",
                                  "__uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16);\n    __type(key, struct dpi_flow_key_v1); __type(value, struct dpi_rt_decision);")
        if not args.controller_binary:
            route_maps.write_text(map_text)
        compile_object(bpfsource/"tc_lan_ingress_route.bpf.c",build/"lan.o")
        (pins/"lan_progs").mkdir(); (pins/"lan_maps").mkdir()
        bpf("prog","loadall",build/"lan.o",pins/"lan_progs","type","classifier","pinmaps",pins/"lan_maps")
        report["tests"].append("actual LAN TC object compiled and kernel verifier accepted")
        for a,b in (("lan0","client0"),("wan1","peer1"),("wan2","peer2")):
            run("ip","link","add",a,"type","veth","peer","name",b); interfaces.append(a)
            run("ip","link","set",a,"up"); run("ip","link","set",b,"up")
        if1,if2=socket.if_nametoindex("wan1"),socket.if_nametoindex("wan2")
        for chain,idx,addr in ((11,if1,"198.18.1.1"),(22,if2,"198.18.2.1")):
            put(pins/"lan_maps/dpi_rt_nat_v1",struct.pack("=I",chain),struct.pack("=I",idx)+socket.inet_aton(addr)+struct.pack("=Q",chain))
        for flow,idx,chain in ((0,if1,11),(1,if1,11),(2,if2,22)):
            for slot in range(16):
                target=struct.pack("=I",idx)+b"\0"*4+b"\0\0"+b"\0"*6+struct.pack("=H",chain)+b"\0\0"
                put(pins/"lan_maps/rt4_slot_map",struct.pack("=II",flow,slot),target)
        put(pins/"lan_maps/dpi_rt_cfg_v1",struct.pack("=I",0),struct.pack("=IIQ",1,1,time.monotonic_ns()+120*r.NS))
        put(pins/"lan_maps/dpi_rt_cli_v1",r.client_key("10.10.10.69"),struct.pack("=I",1))
        def hint(appid=42,flow=2,proto=6,expiry=None):
            hintkey=bytearray(key(1,proto)); hintkey[36:38]=b"\0\0"
            put(pins/"lan_maps/dpi_rt_hint_v1",bytes(hintkey),struct.pack("=QIIII",expiry or time.monotonic_ns()+120*r.NS,appid,flow,1,0))
        # Compile native NAT stage twice. Only rodata initializers and test
        # timeouts differ; actual NAT allocation/state/translation code is used.
        for n,addr in ((1,"198.18.1.1"),(2,"198.18.2.1")):
            override=build/("wan%d"%n); (override/"nat").mkdir(parents=True)
            ro=(bpfsource/"nat/nat_rodata.h").read_text().replace("const volatile u32 wan_ro_addr4 = 0;",
                "const volatile u32 wan_ro_addr4 = %d;"%struct.unpack("=I",socket.inet_aton(addr))[0])
            (override/"nat/nat_rodata.h").write_text(ro)
            common=(bpfsource/"nat/nat_common.h").read_text()
            for name in ("TCP_SYN_TIMEOUT","TCP_TIMEOUT","UDP_TIMEOUT","REPORT_INTERVAL"):
                import re
                common=re.sub(r"(const volatile u64 "+name+r" = )[^;]+;",r"\g<1>"+("100000000;" if name == "REPORT_INTERVAL" else "2000000000;"),common)
            (override/"nat/nat_common.h").write_text(common)
            compile_object(bpfsource/"tc_nat4.bpf.c",build/("nat%d.o"%n),override)
            natpins=pins/("nat%d"%n); natpins.mkdir(); mapdir=pins/("nat%d_maps"%n); mapdir.mkdir()
            cmd=["prog","loadall",build/("nat%d.o"%n),natpins,"type","classifier","pinmaps",mapdir]
            for name in r.MAPS:
                cmd += ["map","name",name,"pinned",pins/"lan_maps"/name]
            bpf(*cmd)
            for proto in ("tcp","udp"):
                for port in range(40000,40064):
                    value=struct.pack("!H",port)+b"\0\0"
                    bpf("map","push","pinned",mapdir/("nat4_%s_port_queue"%proto),"value","hex",*value.hex(" ").split())
            run("tc","qdisc","add","dev","wan%d"%n,"clsact")
            run("tc","filter","add","dev","wan%d"%n,"egress","bpf","da","pinned",natpins/"tc_nat_wan_egress_v4")
        report["tests"].append("both native NAT4 objects compiled, verifier accepted and attached only to isolated veth")
        run("tc","qdisc","add","dev","lan0","clsact")
        run("tc","filter","add","dev","lan0","ingress","bpf","da","pinned",pins/"lan_progs/tc_route4_lan_ingress")
        tx=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));tx.bind(("client0",0));sockets.append(tx)
        rx=[]
        for name in ("peer1","peer2"):
            s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind((name,0));s.setblocking(False);sockets.append(s);rx.append(s)
        def transmit(pkt):
            for sock in rx:
                while True:
                    try:sock.recv(65535)
                    except BlockingIOError:break
            tx.send(pkt); time.sleep(.06)
            found=[]
            for index,sock in enumerate(rx,1):
                while True:
                    try:
                        raw=sock.recv(65535)
                        if len(raw)>=42 and raw[12:14]==b"\x08\x00" and raw[30:34]==pkt[30:34]:found.append((index,raw))
                    except BlockingIOError:break
            return found
        def expect(sport,wan,proto=6,flags=2,**kw):
            found=transmit(packet(sport,proto,flags,**kw))
            assert [x[0] for x in found]==[wan], (sport,wan,[(x[0],x[1].hex()) for x in found])
            assert found[0][1][26:30]==socket.inet_aton("198.18.%d.1"%wan),"native SNAT source"
            value=route_value(sport,proto,kw.get("dst","203.0.113.5"))
            assert value and struct.unpack_from("=Q",value,24)[0]>0,"real NAT CT token must be bound"
        if args.controller_binary:
            spec = importlib.util.spec_from_file_location("dpi_kernel_control_test", BASE / "kernel_control_test.py")
            control_test = importlib.util.module_from_spec(spec); spec.loader.exec_module(control_test)
            control_test.verify(args, pins, transmit, expect, packet, report)
            report["status"] = "passed"
            print(json.dumps(report, indent=2))
            return
        if args.events:
            events=[json.loads(line) for line in args.events.read_text().splitlines() if line.strip()]
            event_apps={2550017:2,1540005:1,1540009:2}
            policy=r.policy_load({"schema_version":1,"clients":["10.10.10.69"],"hint_ttl_seconds":120,
                "applications":{str(a):{"approved":True,"flow_id":f,"wan_ifname":"wan%d"%f,
                   "learn_endpoint":True,"allow_udp_endpoint_hints":True} for a,f in event_apps.items()},"static_endpoints":[]})
            backend=r.RoutingBackend(pins/"lan_maps"); receiver=r.HintReceiver(policy,backend)
            classifications=[e for e in events if e.get("event")=="classification"]
            assert {e["appid"] for e in classifications} >= set(event_apps)|{1000016}, "Expected full-library three apps plus ordinary HTTP control"
            for index,e in enumerate(classifications):
                # Rebase observation time only for this offline synthetic fixture.
                e["observed_at"]=time.time(); receiver.process(e)
                expect(52000+index,event_apps.get(e["appid"],1),dst=e["flow"]["dst_ip"])
            report["tests"].append("full-library producer events -> HintReceiver -> pinned BPF hints -> correct physical veth/SNAT; ordinary HTTP remained default")
            # Retract a learned app; active route is not deleted.
            e=dict(next(e for e in classifications if e["appid"]==2550017),event="retraction",observed_at=time.time())
            receiver.process(e)
            expect(52100,1,dst=e["flow"]["dst_ip"])
            report["tests"].append("producer retraction withdrew future hint without rewriting active route")
        hint(); expect(50001,2)
        report["tests"].append("TCP first SYN selected WAN2 and native NAT4 bound token/SNAT address")
        hint(flow=1); expect(50001,2,flags=16); expect(50002,1)
        report["tests"].append("late changed hint preserved existing WAN2 and selected WAN1 for next connection")
        hint(expiry=1); expect(50003,1)
        report["tests"].append("expired hint uses original default WAN1")
        hint(flow=2,proto=17); expect(51001,2,proto=17)
        # Lease expires; a fresh UDP flow must receive a DEFAULT pin, then
        # retain that default when admission resumes on the very same socket.
        put(pins/"lan_maps/dpi_rt_cfg_v1",struct.pack("=I",0),struct.pack("=IIQ",1,1,1))
        expect(51002,1,proto=17)
        # A live producer can stall beyond its five-second lease. Keep this
        # actual UDP socket tuple active while the expired lease is in effect.
        until=time.monotonic()+6
        while time.monotonic()<until:
            expect(51002,1,proto=17); time.sleep(.15)
        put(pins/"lan_maps/dpi_rt_cfg_v1",struct.pack("=I",0),struct.pack("=IIQ",1,1,time.monotonic_ns()+120*r.NS))
        expect(51002,1,proto=17)
        report["tests"].append("lease gap default UDP connection stayed on WAN1 after admission recovered")
        hint(flow=2,proto=17); expect(51004,2,proto=17)
        # Unloading NAT must make both existing and new controlled flows drop.
        bpf("map","delete","pinned",pins/"lan_maps/dpi_rt_nat_v1","key","hex",*struct.pack("=I",22).hex(" ").split())
        assert transmit(packet(51004,17))==[]
        assert transmit(packet(51005,17))==[]
        put(pins/"lan_maps/dpi_rt_nat_v1",struct.pack("=I",22),struct.pack("=I",if2)+socket.inet_aton("198.18.2.1")+struct.pack("=Q",22))
        expect(51004,2,proto=17)
        report["tests"].append("removing native NAT readiness dropped both pinned and new app flows; restore kept original WAN")
        assert transmit(packet(51001,17,fragment=0x2000))==[]
        assert transmit(packet(51001,17,fragment=1))==[]
        report["tests"].append("first and later IPv4 fragments fail closed, never cross WAN")
        # Native timers need ring-buffer space; this tiny test cannot fill it.
        deadline=time.monotonic()+8
        while route_value(51001,17) is not None and time.monotonic()<deadline: time.sleep(.1)
        assert route_value(51001,17) is None,"native NAT CT timer did not retire route"
        report["tests"].append("real native NAT conntrack timer retired its associated route")
        hint(flow=1,proto=17); expect(51001,1,proto=17)
        report["tests"].append("same UDP tuple after real CT retirement selected new WAN1")
        put(pins/"lan_maps/dpi_rt_cfg_v1",struct.pack("=I",0),struct.pack("=IIQ",1,0,0))
        expect(51001,1,proto=17); expect(51003,1,proto=17)
        report["tests"].append("drain stopped application admission and preserved existing/default flows")
        # NAT endpoint-lock failure must leave only a bounded unbound route.
        expect(55000,1,proto=17,dst="203.0.113.30")
        assert transmit(packet(55000,17,dst="203.0.113.31"))==[]
        pending=route_value(55000,17,"203.0.113.31")
        assert pending and struct.unpack_from("=Q",pending,24)[0]==0
        deadline=time.monotonic()+3
        while route_value(55000,17,"203.0.113.31") is not None and time.monotonic()<deadline:time.sleep(.1)
        assert route_value(55000,17,"203.0.113.31") is None
        report["tests"].append("native NAT endpoint-lock rejection left an unbound route which pending timer safely reclaimed")
        # Stop sending, wait for native CT timers, then explicit quiescent reset.
        deadline=time.monotonic()+8
        while dump(pins/"lan_maps/dpi_rt_flow_v1") and time.monotonic()<deadline: time.sleep(.1)
        assert dump(pins/"lan_maps/dpi_rt_flow_v1")==[],"route decisions remain after CT drain"
        # Real kernel HASH capacity: no untracked SYN/UDP may be transmitted.
        dummy=[]
        for i in range(16):
            flow=bytearray(key(56000+i,17)); flow[4:8]=socket.inet_aton("10.10.10.99")
            dummy.append(bytes(flow)); put(pins/"lan_maps/dpi_rt_flow_v1",bytes(flow),bytes(96))
        put(pins/"lan_maps/dpi_rt_cfg_v1",struct.pack("=I",0),struct.pack("=IIQ",1,1,time.monotonic_ns()+120*r.NS))
        hint(flow=2); hint(flow=2,proto=17)
        assert transmit(packet(57001))==[] and transmit(packet(57002,17))==[]
        for flow in dummy:bpf("map","delete","pinned",pins/"lan_maps/dpi_rt_flow_v1","key","hex",*flow.hex(" ").split())
        expect(57001,2); expect(57002,2,proto=17)
        report["tests"].append("full connection map failed closed for TCP and UDP; after capacity recovered their first transmitted packet used pinned WAN2")
        # Same ifindex/address/chain but a new native instance epoch must not
        # accept the existing pin. This is a controlled registry-generation
        # injection; the normal CT timer test above exercised actual retirement.
        put(pins/"lan_maps/dpi_rt_nat_v1",struct.pack("=I",22),struct.pack("=I",if2)+socket.inet_aton("198.18.2.1")+struct.pack("=Q",23))
        assert transmit(packet(57001,flags=16))==[]
        assert transmit(packet(57002,17))==[]
        deadline=time.monotonic()+3
        while route_value(57002,17) is not None and time.monotonic()<deadline:time.sleep(.1)
        assert route_value(57002,17) is None
        report["tests"].append("same-address native NAT instance epoch change failed closed and retired old-generation pins")
        put(pins/"lan_maps/dpi_rt_cfg_v1",struct.pack("=I",0),struct.pack("=IIQ",1,0,0))
        backend=r.RoutingBackend(pins/"lan_maps"); backend.reset_quiescent()
        assert backend.status()["armed"] is False
        report["tests"].append("quiescent drain plus owned-map reset restored unarmed route path")
        report["status"]="passed"
    except Exception as exc:
        report["status"]="failed"; report["error"]=str(exc); raise
    finally:
        (args.output/"result.json").write_text(json.dumps(report,indent=2)+"\n")
        for sock in sockets:sock.close()
        for dev in interfaces:
            subprocess.run(["ip","link","del",dev],capture_output=True)
        for leaf in sorted(pins.rglob("*"),key=lambda p:len(p.parts),reverse=True):
            if leaf.is_dir():leaf.rmdir()
            else:leaf.unlink()
        pins.rmdir()
    print(json.dumps(report,indent=2))
if __name__=="__main__":main()
