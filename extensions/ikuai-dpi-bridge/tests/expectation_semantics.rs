use dpi_bridge::matcher::{Matcher,expect::{ExpectTable,ExpectSpec,FlowIdentity,PacketState}};
use serde_json::json;
use std::{collections::HashSet,fs,sync::atomic::{AtomicU64,Ordering}};
static ID:AtomicU64=AtomicU64::new(0);
fn state(client:&str,server:&str,sport:u16,dport:u16,proto:u8,dir:u8,t:u64)->PacketState {
 PacketState{flow:FlowIdentity{client_ip:client.parse().unwrap(),server_ip:server.parse().unwrap(),client_port:sport,server_port:dport,protocol:proto},direction:dir,now_ms:t}
}
fn source()->PacketState {state("10.0.0.1","198.51.100.1",40000,443,6,1,0)}
fn spec(kind:u8)->ExpectSpec {ExpectSpec{protocol:17,kind,age:2,count:0,before:true,appid:9001,weak:false,timeout_secs:1200}}
fn load(v:serde_json::Value)->Matcher {
 let p=std::env::temp_dir().join(format!("dpi-expect-{}-{}.json",std::process::id(),ID.fetch_add(1,Ordering::Relaxed)));
 fs::write(&p,serde_json::to_vec(&v).unwrap()).unwrap();let m=Matcher::load(&p,&HashSet::new()).unwrap();fs::remove_file(p).unwrap();m
}
fn rule()->serde_json::Value {json!({"_type":"IK_APP","proto":6,"dir":1,"pkt_seq":1,"appid":9001,"rule_id":42,"data":{"hex":"4142"},"match_method":0,
 "expect_conn":{"_type":"EXPECT","proto":17,"type":1,"age":2,"count":0,"before":true,"after":0,"app_id":9001,"timeout":1200}})}
#[test]
fn sports_expectation_is_client_isolated_and_has_its_own_transport() {
 let mut t=ExpectTable::default();t.learn(&spec(1),42,&source()).unwrap();
 for s in [state("10.0.0.2","203.0.113.1",40000,9999,17,1,1),state("10.0.0.1","203.0.113.1",40001,9999,17,1,2),state("10.0.0.1","203.0.113.1",40000,9999,6,1,3)] {assert!(t.lookup(&s).unwrap().is_none());}
 let hit=t.lookup(&state("10.0.0.1","203.0.113.1",40000,9999,17,1,4)).unwrap().unwrap();
 assert_eq!((hit.appid,hit.priority,hit.rule_id),(9001,100,42));
}
#[test]
fn all_four_tuple_types_keep_their_independent_predicates() {
 for kind in [1,2,4,8] {
  let mut t=ExpectTable::default();t.learn(&spec(kind),42,&source()).unwrap();
  let good=state("10.0.0.1","198.51.100.1",40000,443,17,1,1);assert!(t.lookup(&good).unwrap().is_some());
  let other_addr=state("10.0.0.1","203.0.113.1",40000,443,17,1,2);assert_eq!(t.lookup(&other_addr).unwrap().is_some(),kind==1);
  let other_sport=state("10.0.0.1","198.51.100.1",40001,443,17,1,3);assert_eq!(t.lookup(&other_sport).unwrap().is_some(),[4,8].contains(&kind));
  let other_dport=state("10.0.0.1","198.51.100.1",40000,444,17,1,4);assert_eq!(t.lookup(&other_dport).unwrap().is_some(),kind!=4);
 }
}
#[test]
fn reply_learning_uses_original_tuple_but_packet_lookup_uses_wire_direction() {
 let mut t=ExpectTable::default();let mut s=source();s.direction=2;t.learn(&spec(1),42,&s).unwrap();
 let reply=state("10.0.0.1","203.0.113.1",40000,9999,17,2,1);assert!(t.lookup(&reply).unwrap().is_none());
 let mut original=reply;original.direction=1;original.now_ms=2;assert!(t.lookup(&original).unwrap().is_some());
}
#[test]
fn strong_precedes_weak_across_types_and_newest_strong_wins_within_type() {
 let mut t=ExpectTable::default();let mut strong=spec(8);strong.appid=22;t.learn(&strong,22,&source()).unwrap();
 let mut weak=spec(1);weak.weak=true;weak.appid=11;t.learn(&weak,11,&source()).unwrap();
 let future=state("10.0.0.1","198.51.100.1",40000,9,17,1,1);assert_eq!(t.lookup(&future).unwrap().unwrap().appid,22);
 let mut t=ExpectTable::default();t.learn(&spec(1),42,&source()).unwrap();let mut newer=spec(1);newer.appid=33;t.learn(&newer,33,&source()).unwrap();
 assert_eq!(t.lookup(&future).unwrap().unwrap().appid,33);
 let mut t=ExpectTable::default();t.learn(&weak,11,&source()).unwrap();assert_eq!(t.lookup(&future).unwrap().unwrap().priority,5);
}
#[test]
fn before_invalidates_existing_negative_lookup_but_after_only_does_not() {
 for before in [false,true] {
  let mut t=ExpectTable::default();let mut future=state("10.0.0.1","203.0.113.1",40000,9,17,1,0);assert!(t.lookup(&future).unwrap().is_none());
  let mut s=spec(1);s.before=before;let mut from=source();from.now_ms=1;t.learn(&s,42,&from).unwrap();future.now_ms=2;
  assert_eq!(t.lookup(&future).unwrap().is_some(),before);
  let fresh=state("10.0.0.1","203.0.113.2",40000,9,17,1,3);assert!(t.lookup(&fresh).unwrap().is_some());
 }
}
#[test]
fn repeated_packet_is_not_a_repeated_state_transition() {
 let mut t=ExpectTable::default();t.learn(&spec(1),42,&source()).unwrap();let mut future=state("10.0.0.1","203.0.113.1",40000,9,17,1,1);
 assert!(t.lookup(&future).unwrap().is_some());future.now_ms=2;assert!(t.lookup(&future).unwrap().is_none());
}
#[test]
fn expiration_uses_strict_boundary_and_match_refreshes_lifetime() {
 let mut t=ExpectTable::default();let mut s=spec(1);s.timeout_secs=1;t.learn(&s,42,&source()).unwrap();
 assert_eq!(t.expire(1000).unwrap(),0);assert_eq!(t.expire(1003).unwrap(),0);assert_eq!(t.expire(1004).unwrap(),1);
 let mut t=ExpectTable::default();t.learn(&s,42,&source()).unwrap();let future=state("10.0.0.1","203.0.113.1",40000,9,17,1,500);assert!(t.lookup(&future).unwrap().is_some());
 assert_eq!(t.expire(1500).unwrap(),0);assert_eq!(t.expire(1504).unwrap(),1);
}
#[test]
fn duplicate_creation_preserves_native_age_tick_refresh_quirk() {
 let mut t=ExpectTable::default();t.learn(&spec(1),42,&source()).unwrap();let mut s=source();s.now_ms=100;
 let change=t.learn(&spec(1),42,&s).unwrap();assert_eq!(change.expires_at_ms,108);assert_eq!(change.action,"refreshed_native_age_ticks");
 assert_eq!(t.expire(108).unwrap(),0);assert_eq!(t.expire(111).unwrap(),0);assert_eq!(t.expire(112).unwrap(),1);
}
#[test]
fn expiry_fast_path_does_not_skip_an_earlier_deadline_after_refresh() {
 let mut t=ExpectTable::default();let mut first=spec(1);first.timeout_secs=1;t.learn(&first,42,&source()).unwrap();
 let mut second=source();second.flow.client_port=40001;let mut other=spec(1);other.timeout_secs=2;t.learn(&other,43,&second).unwrap();
 assert!(t.lookup(&state("10.0.0.1","203.0.113.1",40000,9,17,1,500)).unwrap().is_some());
 assert_eq!(t.expire(1004).unwrap(),0);assert_eq!(t.expire(1504).unwrap(),1);assert_eq!(t.len(),1);
 assert_eq!(t.expire(2004).unwrap(),1);
}
#[test]
fn obsolete_client_generations_cannot_accumulate_outside_table_bounds() {
 let mut t=ExpectTable::new(2,2);
 for n in 1..=100 {
  let mut s=source();s.flow.client_ip=std::net::Ipv4Addr::from(0x0a000000+n);s.now_ms=n as u64*2000;
  let mut e=spec(1);e.timeout_secs=1;t.learn(&e,42,&s).unwrap();
  t.revoke_flow(&s.flow);assert!(t.client_generation_count()<=2);
 }
 t.expire(202000).unwrap();assert_eq!(t.client_generation_count(),0);
}
#[test]
fn clocks_capacity_and_explicit_revocation_fail_closed() {
 let mut t=ExpectTable::new(1,3);t.learn(&spec(1),42,&source()).unwrap();let mut different=source();different.flow.client_port=40001;different.now_ms=1;
 assert!(t.learn(&spec(1),43,&different).is_err());assert_eq!(t.len(),1);assert!(t.expire(0).is_err());
 assert_eq!(t.revoke_source(&source().flow),1);assert!(t.revoke_flow(&source().flow));
 t.learn(&spec(1),43,&different).unwrap();assert_eq!(t.revoke_client(different.flow.client_ip),1);assert_eq!(t.flow_count(),0);
 t.clear();assert!(t.expire(0).is_ok());
 let mut t=ExpectTable::new(2,0);assert!(t.lookup(&source()).is_err());assert!(t.is_empty());
}
#[test]
fn per_client_type_capacity_is_512() {
 let mut t=ExpectTable::new(1024,2048);
 for port in 1..=512 {let mut s=source();s.flow.client_port=port;t.learn(&spec(1),42,&s).unwrap();}
 let mut s=source();s.flow.client_port=513;assert!(t.learn(&spec(1),42,&s).is_err());assert_eq!(t.len(),512);
 // A second type has its own bounded list.
 t.learn(&spec(8),42,&s).unwrap();assert_eq!(t.len(),513);
}
#[test]
fn matcher_requires_explicit_state_and_learns_actual_cross_flow_result() {
 let m=load(rule());assert_eq!(m.audit["compiled_rules"],1);assert_eq!(m.audit["stateful_rules"],1);
 assert!(m.match_packet(6,1,1,443,b"AB").unwrap().is_empty());
 let mut t=ExpectTable::default();let r=m.match_packet_stateful(1,b"AB",&mut t,&source()).unwrap();assert_eq!(r.hits.len(),1);assert_eq!(r.state_changes.len(),1);
 let future=state("10.0.0.1","203.0.113.1",40000,9999,17,1,1);let r=m.match_packet_stateful(1,b"not-AB",&mut t,&future).unwrap();
 assert!(r.hits.is_empty());assert_eq!(r.expectation_hits.len(),1);assert_eq!(r.expectation_hits[0].appid,9001);
}
#[test]
fn conflicting_or_optional_candidate_actions_do_not_learn() {
 let a=rule();let mut b=a.clone();b["rule_id"]=json!(43);b["expect_conn"]["app_id"]=json!(9002);
 for second in [b,{let mut b=a.clone();b["rule_id"]=json!(44);b.as_object_mut().unwrap().remove("expect_conn");b}] {
  let m=load(json!([a,second]));let mut t=ExpectTable::default();let r=m.match_packet_stateful(1,b"AB",&mut t,&source()).unwrap();
  assert_eq!(r.hits.len(),2);assert!(r.state_changes.is_empty());assert_eq!(r.state_issues.len(),1);assert!(t.is_empty());
 }
}
#[test]
fn unsupported_future_expect_semantics_are_not_silently_discarded() {
 for (field,value) in [("after",json!(1)),("count",json!(1)),("match_flag",json!(2)),("timeout",json!(0)),("before",json!(1))] {
  let mut a=rule();a["expect_conn"][field]=value;assert_eq!(load(a).audit["compiled_rules"],0,"{field}");
 }
}
#[test]
fn actual_expect_bracket_rules_keep_vendor_class_grammar() {
 let cases=[
  (10312448,r"\[\[\[\[\[.[^\[][^\[][^\[]\[\[[^\[]\[[^\[]$",["[[[[[","A","B","C","D","[[","E","[","F"].concat()),
  (10312450,r"\]\]\]\]\].[^\]][^\]][^\]]\]\][^\]]\][^\]]$",["]]]]]","A","B]","C]","D]","]]","E]","]","F]"].concat()),
 ];
 for (id,pattern,payload) in cases {
  let mut a=rule();a["rule_id"]=json!(id);a["data"]=json!(pattern);a["match_method"]=json!(1);let m=load(a);assert_eq!(m.audit["compiled_rules"],1);
  let mut t=ExpectTable::default();let r=m.match_packet_stateful(1,payload.as_bytes(),&mut t,&source()).unwrap();assert_eq!(r.hits.len(),1,"{id} {payload}");assert_eq!(r.state_changes.len(),1);
  let mut t=ExpectTable::default();let mut wrong=payload.into_bytes();wrong[6]=b'\\';let r=m.match_packet_stateful(1,&wrong,&mut t,&source()).unwrap();assert!(r.hits.is_empty(),"{id}");assert!(t.is_empty());
 }
}
