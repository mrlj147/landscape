use dpi_bridge::{matcher::Matcher,packet::Packet,replay::{Cidr,Replay}};
use std::{collections::HashSet,net::IpAddr,sync::atomic::{AtomicUsize,Ordering}};
static N:AtomicUsize=AtomicUsize::new(0);
fn matcher()->Matcher {
    let path=std::env::temp_dir().join(format!("dpi-test-{}-{}.json",std::process::id(),N.fetch_add(1,Ordering::SeqCst)));
    // Bare rules deliberately have no unverified vendor container semantics.
    let rules=r#"[{"_type":"IK_APP","appid":2550017,"rule_id":1,"dir":1,"proto":0,"pkt_seq":0,"match_method":5,"data":"steam-marker"},{"_type":"IK_APP","appid":1540009,"rule_id":2,"dir":1,"proto":6,"pkt_seq":0,"match_method":5,"data":"leishen-marker"}]"#;
    std::fs::write(&path,rules).unwrap();let m=Matcher::load(&path,&HashSet::new()).unwrap();std::fs::remove_file(path).unwrap();m
}
fn pkt(dir:u8,seq:u32,flags:u8,payload:&[u8])->Packet {
    let (src,dst,sp,dp)=if dir==1 {("10.10.10.69","203.0.113.8",50000,80)} else {("203.0.113.8","10.10.10.69",80,50000)};
    Packet{src_ip:src.parse().unwrap(),dst_ip:dst.parse().unwrap(),src_port:sp,dst_port:dp,protocol:6,tcp_seq:Some(seq),syn:flags&2!=0,ack:flags&16!=0,fin:flags&1!=0,rst:flags&4!=0,payload:payload.to_vec()}
}
fn replay(m:&Matcher)->Replay<'_>{Replay::new(m,vec![Cidr::parse("10.10.10.0/24").unwrap()],4).unwrap()}
#[test] fn cidr_bounds_and_dual_stack(){
    assert!(Cidr::parse("10.10.10.0/33").is_err());
    assert!(Cidr::parse("10.0.0.0/0").unwrap().contains("192.168.1.1".parse::<IpAddr>().unwrap()));
    assert!(!Cidr::parse("10.10.10.0/24").unwrap().contains("10.10.11.69".parse().unwrap()));
    assert!(Cidr::parse("fd00::/8").unwrap().contains("fd01::1".parse().unwrap()));
}
#[test] fn midstream_not_assumed_first_packet(){let m=matcher();let mut r=replay(&m);assert!(r.process(1000.0,pkt(1,100,16,b"steam-marker")).unwrap().is_empty());assert_eq!(r.stats["tcp_midstream_skipped"],1);}
#[test] fn classify_refresh_then_retract_on_close(){
    let m=matcher();let mut r=replay(&m);assert!(r.process(1000.0,pkt(1,99,2,b"")).unwrap().is_empty());
    r.process(1000.01,pkt(2,199,18,b"")).unwrap();
    let hit=r.process(1000.1,pkt(1,100,16,b"steam-marker")).unwrap();assert_eq!(hit.len(),1);assert_eq!(hit[0]["appid"],2550017);assert_eq!(hit[0]["flow"]["src_ip"],"10.10.10.69");
    assert!(r.process(1001.0,pkt(1,100,16,b"steam-marker")).unwrap().is_empty()); // retransmit
    let refresh=r.process(1031.0,pkt(2,200,16,b"x")).unwrap();assert_eq!(refresh.len(),1);assert_eq!(refresh[0]["evidence"]["reason"],"active_flow_refresh");
    let end=r.process(1032.0,pkt(1,112,17,b"")).unwrap();assert_eq!(end[0]["event"],"retraction");
    assert!(r.process(1033.0,pkt(2,201,16,b"x")).unwrap().is_empty());
}
#[test] fn gaps_and_partial_overlap_stop_inspection(){
    for seq in [99,101] {let m=matcher();let mut r=replay(&m);r.process(1000.0,pkt(1,99,2,b"")).unwrap();assert!(r.process(1001.0,pkt(1,seq,16,b"steam-marker")).unwrap().is_empty());assert_eq!(r.stats["gaps_or_overlap"],1);}
}
#[test] fn conflicting_apps_retract_and_cannot_refresh(){
    let m=matcher();let mut r=replay(&m);r.process(1000.0,pkt(1,99,2,b"")).unwrap();assert_eq!(r.process(1001.0,pkt(1,100,16,b"steam-marker")).unwrap().len(),1);
    let e=r.process(1002.0,pkt(1,112,16,b"leishen-marker")).unwrap();assert_eq!(e.len(),1);assert_eq!(e[0]["event"],"retraction");
    assert!(r.process(1035.0,pkt(1,126,16,b"steam-marker")).unwrap().is_empty());
}
#[test] fn same_packet_ambiguity_produces_no_label(){let m=matcher();let mut r=replay(&m);r.process(1000.0,pkt(1,99,2,b"")).unwrap();assert!(r.process(1001.0,pkt(1,100,16,b"steam-marker leishen-marker")).unwrap().is_empty());}
#[test] fn tuple_reuse_retracts_old_label(){let m=matcher();let mut r=replay(&m);r.process(1000.0,pkt(1,99,2,b"")).unwrap();r.process(1001.0,pkt(1,100,16,b"steam-marker")).unwrap();let e=r.process(1002.0,pkt(1,999,2,b"")).unwrap();assert_eq!(e[0]["event"],"retraction");assert_eq!(r.process(1003.0,pkt(1,1000,16,b"leishen-marker")).unwrap()[0]["appid"],1540009);}
#[test] fn bounded_flows_expire_without_guessing_midstream(){
    let m=matcher();let mut r=Replay::new(&m,vec![Cidr::parse("10.10.10.0/24").unwrap()],1).unwrap();r.process(1000.0,pkt(1,99,2,b"")).unwrap();
    let mut p=pkt(1,99,2,b"");p.src_port=50001;r.process(1001.0,p).unwrap();assert_eq!(r.stats["flow_limit_drops"],1);
    assert!(r.process(1121.0,pkt(1,100,16,b"steam-marker")).unwrap().is_empty());assert_eq!(r.stats["expired_flows"],1);
}
#[test] fn tcp_fast_open_not_miscounted(){let m=matcher();let mut r=replay(&m);assert!(r.process(1000.0,pkt(1,99,2,b"steam-marker")).unwrap().is_empty());assert!(r.process(1001.0,pkt(1,112,16,b"steam-marker")).unwrap().is_empty());}
#[test] fn unrelated_lan_traffic_ignored(){let m=matcher();let mut r=replay(&m);let mut p=pkt(1,99,2,b"");p.dst_ip="10.10.10.3".parse().unwrap();r.process(1000.0,p).unwrap();assert_eq!(r.stats["ignored"],1);}
#[test] fn old_syn_cannot_destroy_active_label(){let m=matcher();let mut r=replay(&m);r.process(1000.0,pkt(1,99,2,b"")).unwrap();r.process(1001.0,pkt(1,100,16,b"steam-marker")).unwrap();assert!(r.process(999.0,pkt(1,999,2,b"")).unwrap().is_empty());let e=r.process(1032.0,pkt(1,112,16,b"x")).unwrap();assert_eq!(e[0]["event"],"classification");}
#[test] fn delayed_syn_retransmission_does_not_reset_flow(){let m=matcher();let mut r=replay(&m);r.process(1000.0,pkt(1,99,2,b"")).unwrap();r.process(1001.0,pkt(1,100,16,b"steam-marker")).unwrap();assert!(r.process(1002.0,pkt(1,99,2,b"")).unwrap().is_empty());let e=r.process(1003.0,pkt(1,112,16,b"leishen-marker")).unwrap();assert_eq!(e[0]["event"],"retraction");assert_eq!(e[0]["evidence"]["reason"],"conflicting_application_matches");}
#[test] fn classified_flow_gap_retracts_and_never_refreshes(){let m=matcher();let mut r=replay(&m);r.process(1000.0,pkt(1,99,2,b"")).unwrap();r.process(1001.0,pkt(1,100,16,b"steam-marker")).unwrap();let e=r.process(1002.0,pkt(1,115,16,b"x")).unwrap();assert_eq!(e[0]["event"],"retraction");assert!(r.process(1033.0,pkt(1,116,16,b"steam-marker")).unwrap().is_empty());}

fn udp(payload:&[u8])->Packet {let mut p=pkt(1,0,0,payload);p.protocol=17;p.tcp_seq=None;p}
#[test] fn per_flow_expiry_between_gc_ticks(){
 let m=matcher();let mut r=replay(&m);
 assert_eq!(r.process(1000.4,udp(b"steam-marker")).unwrap().len(),1);
 let mut other=pkt(1,900,2,b"");other.src_port=50001;
 assert!(r.process(1120.3,other).unwrap().is_empty());
 let e=r.process(1120.5,udp(b"unrelated")).unwrap();
 assert_eq!(e.len(),1);assert_eq!(e[0]["event"],"retraction");assert_eq!(e[0]["evidence"]["reason"],"idle_expiry");
 assert_eq!(r.stats["expired_flows"],1);
}
#[test] fn global_gc_retracts_expired_labels(){
 let m=matcher();let mut r=replay(&m);r.process(1000.0,udp(b"steam-marker")).unwrap();
 let mut other=pkt(1,900,2,b"");other.src_port=50001;
 let e=r.process(1121.0,other).unwrap();assert_eq!(e.len(),1);assert_eq!(e[0]["event"],"retraction");assert_eq!(e[0]["flow"]["protocol"],"udp");
 assert_eq!(r.stats["retractions"],1);
}
