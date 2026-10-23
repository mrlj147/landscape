use dpi_bridge::{matcher::{decide,Hit,Matcher,expect::{ExpectTable,FlowIdentity,PacketState}},packet::Packet,replay::{Cidr,Replay}};
use serde_json::{json,Value};
use std::{collections::HashSet,sync::atomic::{AtomicUsize,Ordering}};
static ID:AtomicUsize=AtomicUsize::new(0);
fn load(rules:Value)->Matcher {
 let p=std::env::temp_dir().join(format!("dpi-priority-{}-{}.json",std::process::id(),ID.fetch_add(1,Ordering::Relaxed)));
 std::fs::write(&p,rules.to_string()).unwrap();let m=Matcher::load(&p,&HashSet::new()).unwrap();std::fs::remove_file(p).unwrap();m
}
fn rule(app:u32,id:u32,priority:u32,data:&str)->Value {json!({"_type":"IK_APP","appid":app,"rule_id":id,"priority":priority,"proto":17,"dir":1,"pkt_seq":0,"data":data,"match_method":5})}
fn action(app:u32)->Value {json!({"proto":17,"type":1,"age":2,"count":0,"before":true,"after":0,"app_id":app,"timeout":1200})}
fn hit(app:u32,id:u32,p:u32)->Hit{Hit{appid:app,rule_id:id,priority:p,kind:"payload".into()}}
fn packet(server:&str,data:&[u8])->Packet {Packet{src_ip:"10.0.0.1".parse().unwrap(),dst_ip:server.parse().unwrap(),src_port:40000,dst_port:443,protocol:17,tcp_seq:None,syn:false,ack:false,fin:false,rst:false,payload:data.to_vec()}}
fn state()->PacketState {PacketState{flow:FlowIdentity{client_ip:"10.0.0.1".parse().unwrap(),server_ip:"198.51.100.1".parse().unwrap(),client_port:40000,server_port:443,protocol:17},direction:1,now_ms:0}}
fn replay(m:&Matcher)->Replay<'_>{Replay::new(m,vec![Cidr::parse("10.0.0.0/24").unwrap()],32).unwrap()}
#[test]
fn unique_highest_application_wins_without_erasing_lower_hits(){
 let hits=vec![hit(1,1,99),hit(2,2,105),hit(3,3,200),hit(3,4,200)];let d=decide(&hits);
 assert!(!d.ambiguous);assert_eq!(d.appids,vec![3]);assert_eq!(d.winner.unwrap().rule_id,3);assert_eq!(hits.len(),4);
 let m=load(json!([rule(1,1,99,"GET"),rule(2,2,200,"steam")]));let mut r=replay(&m);
 let e=r.process(1.0,packet("198.51.100.1",b"GET steam")).unwrap();assert_eq!(e.len(),1);assert_eq!(e[0]["appid"],2);assert_eq!(e[0]["evidence"]["packet_hits"].as_array().unwrap().len(),2);
}
#[test]
fn equal_highest_different_apps_refuse_even_with_lower_candidates(){
 let d=decide(&[hit(1,1,200),hit(2,2,200),hit(3,3,5)]);assert!(d.ambiguous);assert!(d.winner.is_none());assert_eq!(d.appids,vec![1,2]);
 let m=load(json!([rule(1,1,200,"same"),rule(2,2,200,"same")]));let mut r=replay(&m);
 assert!(r.process(1.0,packet("198.51.100.1",b"same")).unwrap().is_empty());assert_eq!(r.stats["ambiguous_flows"],1);
}
#[test]
fn stronger_later_packet_retracts_then_reclassifies_and_never_downgrades(){
 let m=load(json!([rule(1,1,99,"generic"),rule(2,2,200,"specific")]));let mut r=replay(&m);
 assert_eq!(r.process(1.0,packet("198.51.100.1",b"generic")).unwrap()[0]["appid"],1);
 let e=r.process(2.0,packet("198.51.100.1",b"specific")).unwrap();assert_eq!(e.len(),2);assert_eq!(e[0]["event"],"retraction");assert_eq!(e[0]["appid"],1);assert_eq!(e[1]["event"],"classification");assert_eq!(e[1]["appid"],2);
 let e=r.process(33.0,packet("198.51.100.1",b"generic")).unwrap();assert_eq!(e.len(),1);assert_eq!(e[0]["appid"],2);assert_eq!(e[0]["evidence"]["priority"],200);
}
#[test]
fn equal_priority_cross_packet_conflict_retracts_and_stays_closed(){
 let m=load(json!([rule(1,1,200,"alpha"),rule(2,2,200,"beta"),rule(3,3,250,"later")]));let mut r=replay(&m);
 r.process(1.0,packet("198.51.100.1",b"alpha")).unwrap();let e=r.process(2.0,packet("198.51.100.1",b"beta")).unwrap();assert_eq!(e.len(),1);assert_eq!(e[0]["event"],"retraction");
 assert!(r.process(33.0,packet("198.51.100.1",b"later")).unwrap().is_empty());
}
#[test]
fn expected_actions_only_follow_the_unique_highest_winner(){
 let mut learn=rule(2,2,200,"specific");learn["expect_conn"]=action(2);
 let m=load(json!([rule(1,1,99,"generic"),learn]));let mut t=ExpectTable::default();
 let out=m.match_packet_stateful(1,b"generic specific",&mut t,&state()).unwrap();assert_eq!(out.hits.len(),2);assert_eq!(out.decision.winner.unwrap().appid,2);assert_eq!(out.state_changes.len(),1);assert!(out.state_issues.is_empty());assert_eq!(t.len(),1);
 let mut learn=rule(1,1,80,"generic");learn["expect_conn"]=action(1);
 let m=load(json!([learn,rule(2,2,200,"specific")]));let mut t=ExpectTable::default();
 let out=m.match_packet_stateful(1,b"generic specific",&mut t,&state()).unwrap();assert!(out.state_changes.is_empty());assert!(out.state_issues.is_empty());assert!(t.is_empty());
}
#[test]
fn incumbent_higher_label_prevents_later_lower_action(){
 let mut learn=rule(1,1,80,"learn");learn["expect_conn"]=action(1);let m=load(json!([learn]));let mut t=ExpectTable::default();
 let out=m.match_packet_stateful_with_incumbent(2,b"learn",&mut t,&state(),Some(&hit(2,2,200))).unwrap();assert_eq!(out.decision.winner.unwrap().appid,2);assert!(out.state_changes.is_empty());assert!(t.is_empty());
}
#[test]
fn source_upgrade_revokes_old_learning_and_children_before_using_new_action(){
 let mut low=rule(1,1,80,"low");low["expect_conn"]=action(1);let mut high=rule(2,2,200,"high");high["expect_conn"]=action(2);
 let m=load(json!([low,high]));let mut r=replay(&m);
 assert_eq!(r.process(1.0,packet("198.51.100.1",b"low")).unwrap()[0]["appid"],1);
 let e=r.process(2.0,packet("203.0.113.1",b"child")).unwrap();assert_eq!(e[0]["appid"],1);assert_eq!(e[0]["evidence"]["kind"],"expectation");
 let e=r.process(3.0,packet("198.51.100.1",b"high")).unwrap();assert_eq!(e.len(),3);assert_eq!(e.iter().filter(|v|v["event"]=="retraction").count(),2);assert_eq!(e.last().unwrap()["appid"],2);
 assert!(e.iter().any(|v|v["evidence"]["reason"]=="expectation_source_reclassified"));
 let e=r.process(4.0,packet("203.0.113.2",b"new child")).unwrap();assert_eq!(e[0]["appid"],2);assert_eq!(e[0]["evidence"]["kind"],"expectation");
 assert!(r.process(34.0,packet("203.0.113.1",b"old child")).unwrap().is_empty());
}
