use dpi_bridge::{matcher::Matcher,packet::{Packet,Capture},replay::{self,Cidr,Replay}};
use serde_json::{json,Value};
use std::{collections::HashSet,io::Cursor,net::IpAddr,sync::atomic::{AtomicUsize,Ordering}};
static ID:AtomicUsize=AtomicUsize::new(0);
fn matcher(trigger:u8,expected:u8,before:bool,conflict:bool)->Matcher {
 let a=json!({"_type":"IK_APP","appid":9001,"rule_id":1,"dir":1,"proto":trigger,"pkt_seq":0,"match_method":0,"data":"learn",
 "expect_conn":{"proto":expected,"type":1,"age":2,"count":0,"before":before,"after":0,"app_id":9001,"timeout":1200}});
 let mut b=a.clone();b["rule_id"]=json!(2);b["expect_conn"]["app_id"]=json!(9002);
 let path=std::env::temp_dir().join(format!("dpi-replay-expect-{}-{}.json",std::process::id(),ID.fetch_add(1,Ordering::Relaxed)));
 std::fs::write(&path,serde_json::to_vec(&if conflict{json!([a,b])}else{json!([a])}).unwrap()).unwrap();
 let m=Matcher::load(&path,&HashSet::new()).unwrap();std::fs::remove_file(path).unwrap();m
}
fn packet(proto:u8,client:&str,server:&str,port:u16,seq:u32,flags:u8,payload:&[u8])->Packet {
 Packet{src_ip:client.parse().unwrap(),dst_ip:server.parse().unwrap(),src_port:port,dst_port:443,protocol:proto,tcp_seq:if proto==6{Some(seq)}else{None},syn:flags&2!=0,ack:flags&16!=0,fin:flags&1!=0,rst:flags&4!=0,payload:payload.to_vec()}
}
fn run(m:&Matcher)->Replay<'_>{Replay::new(m,vec![Cidr::parse("10.0.0.0/24").unwrap()],32).unwrap()}
fn checksum(b:&[u8])->u16 {let mut sum=0_u32;for pair in b.chunks(2){sum+=u16::from_be_bytes([pair[0],*pair.get(1).unwrap_or(&0)]) as u32;}while sum>>16!=0{sum=(sum&65535)+(sum>>16);}!(sum as u16)}
fn wire(p:&Packet)->Vec<u8>{
 let src=match p.src_ip{IpAddr::V4(x)=>x.octets(),_=>unreachable!()};let dst=match p.dst_ip{IpAddr::V4(x)=>x.octets(),_=>unreachable!()};
 let mut l4=vec![0; if p.protocol==6{20}else{8}];l4[..2].copy_from_slice(&p.src_port.to_be_bytes());l4[2..4].copy_from_slice(&p.dst_port.to_be_bytes());
 if p.protocol==6{l4[4..8].copy_from_slice(&p.tcp_seq.unwrap().to_be_bytes());l4[12]=0x50;l4[13]=(if p.syn{2}else{0})|(if p.ack{16}else{0})|(if p.fin{1}else{0})|(if p.rst{4}else{0});}
 else{l4[4..6].copy_from_slice(&((8+p.payload.len()) as u16).to_be_bytes());}
 l4.extend_from_slice(&p.payload);let mut pseudo=Vec::from(src);pseudo.extend_from_slice(&dst);pseudo.extend_from_slice(&[0,p.protocol]);pseudo.extend_from_slice(&(l4.len() as u16).to_be_bytes());pseudo.extend_from_slice(&l4);
 let at=if p.protocol==6{16}else{6};l4[at..at+2].copy_from_slice(&checksum(&pseudo).to_be_bytes());
 let mut ip=vec![0;20];ip[0]=0x45;ip[2..4].copy_from_slice(&((20+l4.len()) as u16).to_be_bytes());ip[8]=64;ip[9]=p.protocol;ip[12..16].copy_from_slice(&src);ip[16..20].copy_from_slice(&dst);let c=checksum(&ip);ip[10..12].copy_from_slice(&c.to_be_bytes());ip.extend(l4);ip
}
fn pcap(records:Vec<(u32,Packet)>)->Vec<u8>{
 let mut out=Vec::new();out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());out.extend_from_slice(&2u16.to_le_bytes());out.extend_from_slice(&4u16.to_le_bytes());
 for n in [0u32,0,262144,101]{out.extend_from_slice(&n.to_le_bytes());}
 for (sec,p) in records{let frame=wire(&p);for n in [sec,0,frame.len() as u32,frame.len() as u32]{out.extend_from_slice(&n.to_le_bytes());}out.extend(frame);}out
}
#[test]
fn actual_pcap_cross_transport_learning_classifies_payload_free_syn_with_client_isolation(){
 let m=matcher(17,6,true,false);let bytes=pcap(vec![
  (10,packet(17,"10.0.0.1","198.51.100.1",40000,0,0,b"learn")),
  (11,packet(6,"10.0.0.2","203.0.113.1",40000,100,2,b"")),
  (12,packet(6,"10.0.0.1","203.0.113.1",40000,100,2,b"")),
 ]);
 let mut capture=Capture::new(Cursor::new(bytes)).unwrap();let mut r=run(&m);let mut events=Vec::new();
 replay::run(&mut capture,&mut r,|v|{events.push(v);Ok(())}).unwrap();
 assert_eq!(capture.packets_read,3);assert_eq!(events.len(),2);assert_eq!(events[1]["evidence"]["kind"],"expectation");assert_eq!(events[1]["evidence"]["packet_index"],0);assert_eq!(events[1]["flow"]["src_ip"],"10.0.0.1");assert_eq!(r.stats["expectation_hits"],1);
}
#[test]
fn expectation_can_reconsider_payload_packet_nine(){
 let m=matcher(6,17,true,false);let mut r=run(&m);
 for n in 1..=8{assert!(r.process(n as f64,packet(17,"10.0.0.1","203.0.113.1",40000,0,0,b"other")).unwrap().is_empty());}
 r.process(9.0,packet(6,"10.0.0.1","198.51.100.1",40000,99,2,b"")).unwrap();
 r.process(10.0,packet(6,"10.0.0.1","198.51.100.1",40000,100,16,b"learn")).unwrap();
 let e=r.process(11.0,packet(17,"10.0.0.1","203.0.113.1",40000,0,0,b"other")).unwrap();
 assert_eq!(e.len(),1);assert_eq!(e[0]["evidence"]["packet_index"],9);assert_eq!(e[0]["evidence"]["kind"],"expectation");
}
#[test]
fn global_time_reversal_on_another_flow_cannot_learn(){
 let m=matcher(17,17,true,false);let mut r=run(&m);r.process(10.0,packet(17,"10.0.0.1","198.51.100.1",40000,0,0,b"other")).unwrap();
 assert!(r.process(9.0,packet(17,"10.0.0.2","198.51.100.1",40000,0,0,b"learn")).unwrap().is_empty());
 assert_eq!(r.stats["clock_reversals"],1);assert_eq!(r.stats["expectation_learns"],0);
}
#[test]
fn unreliable_source_capture_revokes_learning_and_all_dependent_labels(){
 let m=matcher(6,17,true,false);let mut r=run(&m);
 r.process(1.0,packet(6,"10.0.0.1","198.51.100.1",40000,99,2,b"")).unwrap();r.process(2.0,packet(6,"10.0.0.1","198.51.100.1",40000,100,16,b"learn")).unwrap();
 let child=packet(17,"10.0.0.1","203.0.113.1",40000,0,0,b"other");assert_eq!(r.process(3.0,child.clone()).unwrap().len(),1);
 let e=r.process(4.0,packet(6,"10.0.0.1","198.51.100.1",40000,999,16,b"lost")).unwrap();assert_eq!(e.len(),2);assert!(e.iter().all(|v|v["event"]=="retraction"));
 assert!(e.iter().any(|v|v["evidence"]["reason"]=="expectation_source_unreliable"));assert!(r.process(35.0,child).unwrap().is_empty());
 assert!(r.process(36.0,packet(17,"10.0.0.1","203.0.113.2",40000,0,0,b"other")).unwrap().is_empty());
}
#[test]
fn ambiguous_learning_never_emits_a_routing_event(){
 let m=matcher(17,17,true,true);let mut r=run(&m);assert!(r.process(1.0,packet(17,"10.0.0.1","198.51.100.1",40000,0,0,b"learn")).unwrap().is_empty());
 assert_eq!(r.stats["expectation_issues"],1);assert!(r.process(2.0,packet(17,"10.0.0.1","203.0.113.1",40000,0,0,b"other")).unwrap().is_empty());
 assert!(r.process(3.0,packet(17,"10.0.0.1","198.51.100.1",40000,0,0,b"learn")).unwrap().is_empty());assert_eq!(r.stats["expectation_issues"],1);
}
#[test]
fn idle_gc_and_tcp_tuple_reuse_revoke_old_lookup_observations(){
 let m=matcher(17,6,false,false);let mut r=run(&m);let syn=packet(6,"10.0.0.1","203.0.113.1",40000,99,2,b"");
 r.process(1.0,syn.clone()).unwrap();r.process(2.0,packet(17,"10.0.0.1","198.51.100.1",40000,0,0,b"learn")).unwrap();
 assert!(r.process(3.0,packet(6,"10.0.0.1","203.0.113.1",40000,100,16,b"other")).unwrap().is_empty());
 let e=r.process(4.0,packet(6,"10.0.0.1","203.0.113.1",40000,999,2,b"")).unwrap();assert_eq!(e.len(),1);assert_eq!(e[0]["evidence"]["kind"],"expectation");
 let e=r.process(125.0,syn).unwrap();assert!(e.iter().any(|v|v["event"]=="retraction"));assert!(e.iter().any(|v|v["event"]=="classification"));
}
#[test]
fn stateful_match_cli_accepts_explicit_identity_and_shares_state_across_lines(){
 let path=std::env::temp_dir().join(format!("dpi-stateful-cli-{}.json",std::process::id()));
 std::fs::write(&path,json!({"_type":"IK_APP","appid":9001,"rule_id":1,"dir":1,"proto":17,"pkt_seq":1,"match_method":0,"data":"learn","expect_conn":{"proto":17,"type":1,"age":2,"count":0,"before":true,"after":0,"app_id":9001,"timeout":1200}}).to_string()).unwrap();
 let mut child=std::process::Command::new(env!("CARGO_BIN_EXE_dpi-bridge")).args(["stateful-match","--rules",path.to_str().unwrap()]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn().unwrap();
 use std::io::Write;let mut stdin=child.stdin.take().unwrap();
 for (server,payload,t) in [("198.51.100.1","6c6561726e",0),("203.0.113.1","6e6f",1)] {
  writeln!(stdin,"{}",json!({"context":{"protocol":17,"direction":1,"packet_index":1,"server_port":443,"payload_hex":payload},"state":{"flow":{"client_ip":"10.0.0.1","server_ip":server,"client_port":40000,"server_port":443,"protocol":17},"direction":1,"now_ms":t}})).unwrap();
 }
 drop(stdin);let out=child.wait_with_output().unwrap();std::fs::remove_file(path).unwrap();assert!(out.status.success());
 let rows=String::from_utf8(out.stdout).unwrap().lines().map(|l|serde_json::from_str::<Value>(l).unwrap()).collect::<Vec<_>>();assert_eq!(rows.len(),2);assert_eq!(rows[0]["state_changes"].as_array().unwrap().len(),1);assert_eq!(rows[1]["expectation_hits"][0]["appid"],9001);
}
