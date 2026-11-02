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
    policy: MapHandle,
}
#[async_trait::async_trait]
impl RouteTableDataplane for LiveMaps {
    fn add_lan_route(&self, _: LanRouteInfo) {}
    fn del_lan_route(&self, _: LanRouteInfo) {}
    fn replace_wan_slots_v4(&self, flow: u32, targets: &[(WanRouteTarget, u32)]) {
        crate::maps::route::replace_wan_route_slots_v4_with_map(&self.slots, flow, targets);
    }
    fn replace_wan_slots_v6(&self, _: u32, _: &[(WanRouteTarget, u32)]) {}
    fn del_wan_slots_v4(&self, flow: u32) {
        self.replace_wan_slots_v4(flow, &[]);
    }
    fn del_wan_slots_v6(&self, _: u32) {}
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
async fn health(routes: &IpRouteService, id: Uuid, reachable: bool) {
    let mut eval = HealthEvaluator::new(id, 1, 1, 1);
    let sample = TargetProbe {
        target: "198.18.0.2".parse().unwrap(),
        rtt: reachable.then_some(Duration::from_millis(1)),
    };
    // Includes the evaluator's initial warmup round.
    for _ in 0..3 {
        eval.apply_round(&[sample]);
    }
    routes.update_link_health(eval.info().clone()).await;
}
fn packet(port: u16, udp: bool) -> Vec<u8> {
    let base = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]).ipv4(
        [10, 10, 0, 2],
        [203, 0, 113, 10],
        64,
    );
    let mut out = Vec::new();
    if udp {
        base.udp(port, 443).write(&mut out, b"failover").unwrap();
    } else {
        base.tcp(port, 443, 1, 65535).ack(1).write(&mut out, b"failover").unwrap();
    }
    out
}

#[test]
#[ignore = "requires root, network namespaces, veth and BPF; isolated from host routing"]
fn wan_failover_netns_real_traffic() {
    let router = NetNsGuard::create("fo");
    let client = NetNsGuard::create("foc");
    let uplink = NetNsGuard::create("fou");
    let pin = isolated_pin_root("wan-failover");
    let _router = router.enter();
    ip(&["link", "set", "lo", "up"]);
    let lan = VethPair::create_with_netns("fol", &client);
    let wan1 = VethPair::create_with_netns("foa", &uplink);
    let wan2 = VethPair::create_with_netns("fob", &uplink);
    ip(&["addr", "add", "198.18.0.1/30", "dev", wan1.host()]);
    ip(&["addr", "add", "198.18.0.5/30", "dev", wan2.host()]);
    {
        let _peer = uplink.enter();
        ip(&["link", "set", "lo", "up"]);
        ip(&["addr", "add", "198.18.0.2/30", "dev", wan1.peer()]);
        ip(&["addr", "add", "198.18.0.6/30", "dev", wan2.peer()]);
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
    assert!(probe(wan1.host(), "198.18.0.2"));
    assert!(probe(wan2.host(), "198.18.0.6"));
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let routes = IpRouteService::new(Arc::new(LiveMaps {
        slots: MapHandle::from_pinned_path(pin.join("rt4_slot_map")).unwrap(),
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
        for (id, pair, ipaddr) in [(a, &wan1, "198.18.0.1"), (b, &wan2, "198.18.0.5")] {
            let info =
                RouteTargetInfo::dummy(pair.host_ifindex(), pair.host(), ipaddr.parse().unwrap());
            routes
                .insert_ipv4_wan_route(&RouteOwner::Link(id), WanRouteTarget::link(0, info))
                .await;
            health(&routes, id, true).await;
        }
        routes.sync_flow_wan_targets(&[config.clone()]).await;
    });
    let send = |port, udp| {
        let _client = client.enter();
        send_raw_packet(lan.peer(), &packet(port, udp));
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
        dummy_recv_count(&dummy1.maps.dummy_recv_map, false) == 2
    });
    drop(links);
    ip(&["link", "set", wan1.host(), "down"]);
    assert!(!probe(wan1.host(), "198.18.0.2"));
    assert!(probe(wan2.host(), "198.18.0.6"));
    runtime.block_on(async {
        health(&routes, a, false).await;
        routes.sync_flow_wan_targets(&[config.clone()]).await;
    });
    let links = attach_dummies();
    send(10001, false);
    send(10002, true);
    wait_for("failed WAN resets existing affinities to WAN2", Duration::from_secs(3), || {
        dummy_recv_count(&dummy2.maps.dummy_recv_map, false) == 2
    });
    drop(links);
    ip(&["link", "set", wan1.host(), "up"]);
    assert!(probe(wan1.host(), "198.18.0.2"));
    runtime.block_on(async {
        health(&routes, a, true).await;
        routes.sync_flow_wan_targets(&[config.clone()]).await;
    });
    let links = attach_dummies();
    send(10001, false);
    send(10002, true);
    send(10003, false);
    send(10004, true);
    wait_for("old connections remain WAN2", Duration::from_secs(3), || {
        dummy_recv_count(&dummy2.maps.dummy_recv_map, false) == 4
    });
    wait_for("new connections return WAN1", Duration::from_secs(3), || {
        dummy_recv_count(&dummy1.maps.dummy_recv_map, false) == 4
    });
    drop(links);
    // Carrier stays up, but the remote service is unreachable (address removed).
    {
        let _peer = uplink.enter();
        ip(&["addr", "del", "198.18.0.2/30", "dev", wan1.peer()]);
    }
    assert!(!probe(wan1.host(), "198.18.0.2"));
    config.failover.enable = false;
    runtime.block_on(async {
        health(&routes, a, false).await;
        routes.sync_flow_wan_targets(&[config.clone()]).await;
    });
    let _links = attach_dummies();
    send(10005, false);
    wait_for("manual mode still uses WAN1 without Internet", Duration::from_secs(3), || {
        dummy_recv_count(&dummy1.maps.dummy_recv_map, false) == 5
    });
    settle(100);
    assert_eq!(dummy_recv_count(&dummy2.maps.dummy_recv_map, false), 4);
}
