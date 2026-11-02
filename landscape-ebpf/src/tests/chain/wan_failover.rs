//! Real packets traverse the production TC route program between isolated
//! netns/veth devices. The real route selector writes its maps through this
//! adapter; no packet verdict or health result is mocked.
use crate::{
    skel::tc_lan_ingress_route::TcLanIngressRouteSkelBuilder,
    tests::{
        helper::net::{
            NetNsGuard, TCAttach, VethPair, dummy_recv_count, send_raw_packet, settle, wait_for,
        },
        isolated_pin_root,
        test_xdp_dummy::TestXdpDummySkelBuilder,
    },
};
use etherparse::PacketBuilder;
use landscape_common::{
    flow::{FlowConfig, FlowFailoverConfig, FlowTarget, FlowTargetMode, WeightedFlowTarget},
    sys_service::route_service::{
        LanRouteInfo, RouteOwner, RouteTargetInfo, WanRouteTarget, dataplane::RouteTableDataplane,
    },
    wan_link::{HealthEvaluator, TargetProbe},
};
use landscape_core::route::IpRouteService;
use libbpf_rs::{
    MapCore, MapFlags, MapHandle,
    skel::{OpenSkel, SkelBuilder as _},
};
use std::{mem::MaybeUninit, process::Command, sync::Arc, time::Duration};
use uuid::Uuid;

struct LiveMaps {
    slots: MapHandle,
    slots6: MapHandle,
    policy: MapHandle,
}
#[async_trait::async_trait]
impl RouteTableDataplane for LiveMaps {
    fn add_lan_route(&self, _: LanRouteInfo) {}
    fn del_lan_route(&self, _: LanRouteInfo) {}
    fn replace_wan_slots_v4(&self, flow: u32, targets: &[(WanRouteTarget, u32)]) {
        crate::maps::route::replace_wan_route_slots_v4_with_map(&self.slots, flow, targets);
    }
    fn replace_wan_slots_v6(&self, flow: u32, targets: &[(WanRouteTarget, u32)]) {
        crate::maps::route::replace_wan_route_slots_v6_with_map(&self.slots6, flow, targets);
    }
    fn del_wan_slots_v4(&self, flow: u32) {
        self.replace_wan_slots_v4(flow, &[]);
    }
    fn del_wan_slots_v6(&self, flow: u32) {
        self.replace_wan_slots_v6(flow, &[]);
    }
    fn set_connection_generation(&self, flow: u32, ipv6: bool, generation: Option<u64>) {
        let mut key = [0; 8];
        key[..4].copy_from_slice(&flow.to_ne_bytes());
        key[4..].copy_from_slice(&u32::from(ipv6).to_ne_bytes());
        if let Some(generation) = generation {
            self.policy.update(&key, &generation.to_ne_bytes(), MapFlags::ANY).unwrap();
        } else if self.policy.lookup(&key, MapFlags::ANY).unwrap().is_some() {
            self.policy.delete(&key).unwrap();
        }
    }
    async fn sync_kernel_default_ipv4(&self, _: &[RouteTargetInfo]) -> bool {
        true
    }
    fn invalidate_lan_cache(&self) {}
}
fn ip(args: &[&str]) {
    let result = Command::new("ip").args(args).output().unwrap();
    assert!(result.status.success(), "ip {args:?}: {}", String::from_utf8_lossy(&result.stderr));
}
fn probe(iface: &str, peer: &str) -> bool {
    Command::new("ping")
        .args(["-n", "-c", "1", "-W", "1", "-I", iface, peer])
        .output()
        .unwrap()
        .status
        .success()
}
async fn health(routes: &IpRouteService, id: Uuid, reachable: bool, ipv6: bool) {
    let mut eval = HealthEvaluator::new(id, 1, 1, 1);
    let sample = TargetProbe {
        target: "198.18.0.2".parse().unwrap(),
        rtt: reachable.then_some(Duration::from_millis(1)),
    };
    // Includes the evaluator's initial warmup round.
    for _ in 0..3 {
        eval.apply_round(&[sample]);
    }
    routes.update_link_health_for_family(eval.info().clone(), ipv6).await;
}
fn packet(port: u16, udp: bool, ipv6: bool, syn: bool) -> Vec<u8> {
    let ethernet = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]);
    let base = if ipv6 {
        ethernet.ipv6(
            "fd10::2".parse::<std::net::Ipv6Addr>().unwrap().octets(),
            "2001:db8::10".parse::<std::net::Ipv6Addr>().unwrap().octets(),
            64,
        )
    } else {
        ethernet.ipv4([10, 10, 0, 2], [203, 0, 113, 10], 64)
    };
    let mut out = Vec::new();
    if udp {
        base.udp(port, 443).write(&mut out, b"failover").unwrap();
    } else {
        let tcp = base.tcp(port, 443, 99, 65535);
        if syn {
            tcp.syn().write(&mut out, b"").unwrap();
        } else {
            tcp.ack(1).write(&mut out, b"failover").unwrap();
        }
    }
    out
}

#[test]
#[ignore = "requires root, network namespaces, veth and BPF; isolated from host routing"]
fn wan_failover_netns_real_traffic() {
    real_traffic(false);
}

#[test]
#[ignore = "requires root, network namespaces, veth and BPF; isolated from host routing"]
fn wan_failover_netns_real_ipv6_traffic() {
    real_traffic(true);
}

fn real_traffic(ipv6: bool) {
    let (family, own1, own2, peer1, peer2, prefix) = if ipv6 {
        ("-6", "fd00:1::1", "fd00:2::1", "fd00:1::2", "fd00:2::2", "64")
    } else {
        ("-4", "198.18.0.1", "198.18.0.5", "198.18.0.2", "198.18.0.6", "30")
    };
    let address = |action: &str, iface: &str, value: &str| {
        let cidr = format!("{value}/{prefix}");
        let mut args = vec![family, "addr", action, &cidr, "dev", iface];
        if ipv6 && action == "add" {
            args.push("nodad");
        }
        ip(&args);
    };
    let router = NetNsGuard::create("fo");
    let client = NetNsGuard::create("foc");
    let uplink = NetNsGuard::create("fou");
    let pin = isolated_pin_root("wan-failover");
    let _router = router.enter();
    ip(&["link", "set", "lo", "up"]);
    let lan = VethPair::create_with_netns("fol", &client);
    let wan1 = VethPair::create_with_netns("foa", &uplink);
    let wan2 = VethPair::create_with_netns("fob", &uplink);
    address("add", wan1.host(), own1);
    address("add", wan2.host(), own2);
    {
        let _peer = uplink.enter();
        ip(&["link", "set", "lo", "up"]);
        address("add", wan1.peer(), peer1);
        address("add", wan2.peer(), peer2);
    }
    let mut builder = TcLanIngressRouteSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin).unwrap();
    let mut obj = MaybeUninit::uninit();
    let skel = builder.open(&mut obj).unwrap().load().unwrap();
    let _tc = TCAttach::attach_ingress(&skel.progs.tc_lan_ingress_route, lan.host_ifindex() as i32);
    // Runtime-only flow 0 exercises default slot selection; no reserved-id
    // configuration is persisted or accepted by the API.
    let mut db1 = TestXdpDummySkelBuilder::default();
    let mut ob1 = MaybeUninit::uninit();
    let dummy1 = db1.open(&mut ob1).unwrap().load().unwrap();
    let mut db2 = TestXdpDummySkelBuilder::default();
    let mut ob2 = MaybeUninit::uninit();
    let dummy2 = db2.open(&mut ob2).unwrap().load().unwrap();
    // Health probes must reach a responding peer before dummy counters attach.
    assert!(probe(wan1.host(), peer1));
    assert!(probe(wan2.host(), peer2));
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let routes = IpRouteService::new(Arc::new(LiveMaps {
        slots: MapHandle::from_pinned_path(pin.join("rt4_slot_map")).unwrap(),
        slots6: MapHandle::from_pinned_path(pin.join("rt6_slot_map")).unwrap(),
        policy: MapHandle::from_pinned_path(pin.join("rt_conn_policy")).unwrap(),
    }));
    let a = Uuid::from_u128(1);
    let b = Uuid::from_u128(2);
    let mut config = FlowConfig {
        id: Uuid::new_v4(),
        enable: true,
        flow_id: 0,
        flow_match_rules: vec![],
        flow_targets: [a, b]
            .into_iter()
            .map(|link_id| {
                WeightedFlowTarget::new(FlowTarget::Interface { link_id, name: String::new() }, 1)
            })
            .collect(),
        failover: FlowFailoverConfig {
            mode: FlowTargetMode::PrimaryBackup,
            enable: true,
            failback_delay_secs: 0,
            switch_hold_secs: 0,
            unknown_grace_secs: 0,
            ..Default::default()
        },
        name: String::new(),
        remark: String::new(),
        update_at: 0.0,
    };
    runtime.block_on(async {
        for (id, pair, ipaddr) in [(a, &wan1, own1), (b, &wan2, own2)] {
            let info =
                RouteTargetInfo::dummy(pair.host_ifindex(), pair.host(), ipaddr.parse().unwrap());
            if ipv6 {
                routes
                    .insert_ipv6_wan_route(&RouteOwner::Link(id), WanRouteTarget::link(0, info))
                    .await;
            } else {
                routes
                    .insert_ipv4_wan_route(&RouteOwner::Link(id), WanRouteTarget::link(0, info))
                    .await;
            }
            health(&routes, id, true, ipv6).await;
        }
        routes.sync_flow_wan_targets(&[config.clone()]).await;
    });
    let send = |port, udp| {
        let _client = client.enter();
        send_raw_packet(lan.peer(), &packet(port, udp, ipv6, false));
    };
    let attach_dummies = || {
        let _peer = uplink.enter();
        (
            dummy1.progs.xdp_test_dummy.attach_xdp(wan1.peer_ifindex() as i32).unwrap(),
            dummy2.progs.xdp_test_dummy.attach_xdp(wan2.peer_ifindex() as i32).unwrap(),
        )
    };
    let links = attach_dummies();
    send(10001, false);
    send(10002, true);
    wait_for("initial WAN1 TCP and UDP", Duration::from_secs(3), || {
        dummy_recv_count(&dummy1.maps.dummy_recv_map, ipv6) == 2
    });
    drop(links);
    ip(&["link", "set", wan1.host(), "down"]);
    assert!(!probe(wan1.host(), peer1));
    assert!(probe(wan2.host(), peer2));
    runtime.block_on(async {
        health(&routes, a, false, ipv6).await;
        routes.sync_flow_wan_targets(&[config.clone()]).await;
    });
    let links = attach_dummies();
    send(10001, false);
    send(10002, true);
    wait_for("failed WAN resets existing affinities to WAN2", Duration::from_secs(3), || {
        dummy_recv_count(&dummy2.maps.dummy_recv_map, ipv6) == 2
    });
    drop(links);
    ip(&["link", "set", wan1.host(), "up"]);
    assert!(probe(wan1.host(), peer1));
    runtime.block_on(async {
        health(&routes, a, true, ipv6).await;
        routes.sync_flow_wan_targets(&[config.clone()]).await;
    });
    let links = attach_dummies();
    send(10001, false);
    send(10002, true);
    send(10003, false);
    send(10004, true);
    wait_for("old connections remain WAN2", Duration::from_secs(3), || {
        dummy_recv_count(&dummy2.maps.dummy_recv_map, ipv6) == 4
    });
    wait_for("new connections return WAN1", Duration::from_secs(3), || {
        dummy_recv_count(&dummy1.maps.dummy_recv_map, ipv6) == 4
    });
    drop(links);
    // A new TCP SYN reusing an old tuple must select the recovered primary.
    let links = attach_dummies();
    {
        let _client = client.enter();
        send_raw_packet(lan.peer(), &packet(10001, false, ipv6, true));
    }
    wait_for("new SYN reusing a tuple returns WAN1", Duration::from_secs(3), || {
        dummy_recv_count(&dummy1.maps.dummy_recv_map, ipv6) == 5
    });
    drop(links);
    // Carrier stays up, but the remote service is unreachable (address removed).
    {
        let _peer = uplink.enter();
        address("del", wan1.peer(), peer1);
    }
    assert!(!probe(wan1.host(), peer1));
    config.failover.enable = false;
    runtime.block_on(async {
        health(&routes, a, false, ipv6).await;
        routes.sync_flow_wan_targets(&[config.clone()]).await;
    });
    let _links = attach_dummies();
    send(10005, false);
    wait_for("manual mode still uses WAN1 without Internet", Duration::from_secs(3), || {
        dummy_recv_count(&dummy1.maps.dummy_recv_map, ipv6) == 6
    });
    settle(100);
    assert_eq!(dummy_recv_count(&dummy2.maps.dummy_recv_map, ipv6), 4);
}

#[test]
#[ignore = "requires root and isolated netns/veth"]
fn wan_failover_router_rules_restore_and_preserve_lan() {
    use landscape_common::sys_service::route_service::RouterWanPolicy;
    let ns = NetNsGuard::create("for");
    let _enter = ns.enter();
    ip(&["link", "set", "lo", "up"]);
    let wan1 = VethPair::create("fra");
    let wan2 = VethPair::create("frb");
    let lan = VethPair::create("frl");
    ip(&["addr", "add", "198.18.0.1/30", "dev", wan1.host()]);
    ip(&["addr", "add", "198.18.0.5/30", "dev", wan2.host()]);
    ip(&["addr", "add", "10.10.0.1/24", "dev", lan.host()]);
    ip(&["-6", "addr", "add", "fd00:1::1/64", "dev", wan1.host(), "nodad"]);
    ip(&["-6", "addr", "add", "fd00:2::1/64", "dev", wan2.host(), "nodad"]);
    ip(&["route", "add", "default", "via", "198.18.0.6", "dev", wan2.host()]);
    ip(&["-6", "route", "add", "default", "via", "fd00:2::2", "dev", wan2.host()]);
    let policy = RouterWanPolicy {
        ipv4: Some(RouteTargetInfo::new_gateway_v4(
            wan1.host_ifindex(),
            wan1.host(),
            None,
            "198.18.0.1".parse().unwrap(),
            "198.18.0.2".parse().unwrap(),
            false,
        )),
        ipv6: Some(RouteTargetInfo::new_gateway_v6(
            wan1.host_ifindex(),
            wan1.host(),
            None,
            "fd00:1::1".parse().unwrap(),
            "fd00:1::2".parse().unwrap(),
            false,
        )),
    };
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let get = |family, dst, mark: Option<&str>| {
        let mut args = vec!["-j", family, "route", "get", dst];
        if let Some(mark) = mark {
            args.extend(["mark", mark]);
        }
        let output = Command::new("ip").args(args).output().unwrap();
        if !output.status.success() {
            return None;
        }
        let routes: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
        Some(routes[0]["dev"].as_str().unwrap().to_string())
    };
    assert!(rt.block_on(crate::maps::route::sync_router_wan_policy(Some(&policy))));
    assert_eq!(get("-4", "203.0.113.10", None).as_deref(), Some(wan1.host()));
    assert_eq!(get("-6", "2001:db8::10", None).as_deref(), Some(wan1.host()));
    assert_eq!(get("-4", "10.10.0.2", None).as_deref(), Some(lan.host()));
    assert_eq!(
        get("-4", "203.0.113.10", Some("0x1000007")).as_deref(),
        Some(wan2.host()),
        "HostDirect probe must bypass the host failover rule"
    );
    assert!(
        rt.block_on(crate::maps::route::sync_router_wan_policy(Some(&RouterWanPolicy::default())))
    );
    assert!(
        get("-4", "203.0.113.10", None).is_none(),
        "both WANs unavailable must not fall through"
    );
    assert!(get("-6", "2001:db8::10", None).is_none());
    assert_eq!(get("-4", "10.10.0.2", None).as_deref(), Some(lan.host()));
    assert!(rt.block_on(crate::maps::route::sync_router_wan_policy(None)));
    assert_eq!(get("-4", "203.0.113.10", None).as_deref(), Some(wan2.host()));
    assert_eq!(get("-6", "2001:db8::10", None).as_deref(), Some(wan2.host()));
    // An unrelated existing rule at the reserved priority is not overwritten.
    ip(&["rule", "add", "pref", "10427", "table", "main"]);
    assert!(!rt.block_on(crate::maps::route::sync_router_wan_policy(Some(&policy))));
    assert_eq!(get("-4", "203.0.113.10", None).as_deref(), Some(wan2.host()));
}
