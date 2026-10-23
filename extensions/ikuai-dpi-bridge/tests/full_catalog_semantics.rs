use dpi_bridge::matcher::{Matcher,http_headers};
use serde_json::{json,Value};
use std::{collections::HashSet,fs,sync::atomic::{AtomicU64,Ordering}};
static ID:AtomicU64=AtomicU64::new(0);
fn load(v:Value)->Matcher {
 let p=std::env::temp_dir().join(format!("dpi-semantic-{}-{}.json",std::process::id(),ID.fetch_add(1,Ordering::Relaxed)));
 fs::write(&p,serde_json::to_vec(&v).unwrap()).unwrap();
 let r=Matcher::load(&p,&HashSet::new()).unwrap();fs::remove_file(p).unwrap();r
}
fn app()->Value{json!({"_type":"IK_APP","proto":6,"dir":1,"pkt_seq":1,"appid":9001,"rule_id":1,"data":{"hex":"4142"},"match_method":0})}
fn http(headers:Value)->Value{json!({"_type":"IK_HTTP_APP","dir":1,"pkt_seq":1,"appid":9002,"rule_id":2,"http_info":{"_type":"HTTPINFO","header":headers}})}
fn head(index:u64,data:&str,method:u64)->Value{json!({"_type":"HTTPHEADER","index":index,"data":data,"match_method":method})}
fn tree(d:Value)->Value{json!({"metadata":{"source_app_dat_sha256":"a-future-catalog"},"data":{"_type":"APP","extend_ik_data":d}})}
fn matches(m:&Matcher,p:&[u8])->usize{m.match_packet(6,1,1,80,p).unwrap().len()}
#[test]
fn future_catalog_uses_actual_slot_count() {
 let mut slots=vec![json!({"_type":"IK_APP_SLOT"});8];slots[3]["ik_app"]=json!([app()]);
 let m=load(tree(json!({"_type":"EXTEND_IK_DATA","slot":slots})));
 assert_eq!(m.audit["compiled_rules"],1);assert_eq!(m.match_packet(6,1,1,11,b"AB").unwrap().len(),1);
 assert!(m.match_packet(6,1,1,443,b"AB").unwrap().len()==1);
 assert_eq!(matches(&m,b"AB"),0);
}
#[test]
fn prefix_reads_actual_parent_length_and_index() {
 let h=http(json!([head(3,"http://sample",4)]));
 let m=load(tree(json!({"prefix_match_happs":[{"index":3,"offset":2,"hslot_cnt":64,"happs":{"http_app":[h]}}]})));
 assert_eq!(m.audit["compiled_rules"],1);
 assert_eq!(matches(&m,b"GET / HTTP/1.1\r\nReferer: http://sample/path\r\n\r\n"),1);
 assert_eq!(matches(&m,b"GET / HTTP/1.1\r\nHost: http://sample/path\r\n\r\n"),0);
}
#[test]
fn app_prefix_does_not_invent_group_zero_length() {
 let m=load(tree(json!({"prefix_match_apps":[{"offset":2,"hslot_cnt":64,"apps":{"ik_app":[app()]}}]})));
 assert_eq!(m.audit["compiled_rules"],1);assert_eq!(matches(&m,b"AB"),1);assert_eq!(matches(&m,b"AZ"),0);
}
#[test]
fn multifast_retains_other_header_predicates() {
 let h=http(json!([head(56,"mobile",5),head(3,"https://ok/",4)]));
 let m=load(tree(json!({"multifast_happs":[{"index":56,"http_app":[h]}]})));
 assert_eq!(m.audit["compiled_rules"],1);
 assert_eq!(matches(&m,b"GET / HTTP/1.1\r\nX-Requested-With: app-mobile\r\nReferer: https://ok/path\r\n\r\n"),1);
 assert_eq!(matches(&m,b"GET / HTTP/1.1\r\nX-Requested-With: app-mobile\r\nReferer: https://bad/path\r\n\r\n"),0);
 assert_eq!(matches(&m,b"GET / HTTP/1.1\r\nX-Request-With: app-mobile\r\nReferer: https://ok/path\r\n\r\n"),0);
}
#[test]
fn exact_host_and_one_header_containers_are_supported() {
 let m=load(tree(json!({"exact_host_happs":{"http_app":[http(json!([head(1,"sample.test",0),head(0,"/api",4)]))]}})));
 assert_eq!(matches(&m,b"GET /api/x HTTP/1.1\r\nHost: sample.test\r\n\r\n"),1);
 assert_eq!(matches(&m,b"GET /api/x HTTP/1.1\r\nHost: sampleXtest\r\n\r\n"),0);
 let m=load(tree(json!({"one_header_happs":[{"index":37,"happs":{"http_app":[http(json!([head(37,"sample",5)]))]}}]})));
 assert_eq!(matches(&m,b"GET / HTTP/1.1\r\nServer: sample\r\n\r\n"),1);
}
#[test]
fn every_ordinary_http_wire_header_has_the_correct_index() {
 let names=[(1,"Host"),(2,"User-Agent"),(3,"Referer"),(5,"Pragma"),(6,"Accept"),(7,"Cookie"),(8,"Keep-Alive"),(9,"Cache-Control"),(10,"Content-Encoding"),(11,"Content-Language"),(12,"Content-Type"),(13,"Range"),(14,"Content-Length"),(15,"Connection"),(16,"Date"),(17,"Transfer-Encoding"),(18,"Upgrade"),(19,"Via"),(20,"Accept-Charset"),(21,"Accept-Encoding"),(22,"Accept-Language"),(23,"Authorization"),(24,"From"),(25,"If-Modified-Since"),(26,"If-Match"),(27,"If-None-Match"),(28,"If-Range"),(29,"If-Unmodified-Since"),(30,"Max-Forwards"),(31,"Proxy-Authorization"),(32,"Age"),(33,"Location"),(34,"Proxy-Authenticate"),(35,"Public"),(36,"Retry-After"),(37,"Server"),(38,"Vary"),(39,"Warning"),(40,"WWW-Authenticate"),(41,"Allow"),(42,"Content-Base"),(43,"Content-Location"),(44,"Content-MD5"),(45,"Content-Range"),(46,"Etag"),(47,"Expires"),(48,"Last-Modified"),(49,"Version"),(50,"Status"),(56,"X-Requested-With"),(57,"Set-Cookie")];
 for (index,name) in names {
  let request=format!("GET / HTTP/1.1\r\n{}: value\r\n\r\n",name.to_ascii_lowercase());
  let h=http_headers(request.as_bytes()).unwrap();assert_eq!(h.get(&index),Some(&b"value".to_vec()),"{name}");
 }
}
#[test]
fn url_extension_sequence_private_values_and_body_are_distinct() {
 let h=http_headers(b"POST /a/file.TXT?x=.bad HTTP/1.1\r\nHost: test\r\nX-A: first\r\nX-B: second\r\nX-C: third\r\nX-D: ignored\r\nContent-Length: 4\r\n\r\ndata").unwrap();
 assert_eq!(h[&0],b"/a/file.TXT?x=.bad");assert_eq!(h[&52],b"txt");
 assert_eq!(h[&51],b"first");assert_eq!(h[&54],b"second");assert_eq!(h[&55],b"third");
 assert_eq!(h[&53],b"data");assert_eq!(h[&4],vec![0,1,51,54,55,14,53]);
 let h=http_headers(b"GET /a/file.txt/noext HTTP/1.1\r\nHost: test\r\n\r\n").unwrap();assert!(!h.contains_key(&52));
}
#[test]
fn unknown_fields_and_flattened_vendor_rules_fail_closed() {
 let mut a=app();a["expect_conn"]=json!({"app_id":9999});let m=load(a);assert_eq!(m.audit["compiled_rules"],0);
 for key in ["match_flag","multi_data","dup_bytes","dup_block"] {let mut a=app();a[key]=json!({});assert_eq!(load(a).audit["compiled_rules"],0);}
 let m=load(tree(json!({"prefix_match_apps":[{"offset":2,"hslot_cnt":64,"new_constraint":1,"apps":{"ik_app":[app()]}}]})));assert_eq!(m.audit["compiled_rules"],0);
 let m=load(json!({"metadata":{"source_app_dat_sha256":"77d7aa94f443da9815bec5bd5a0862dd0c887ea7b5d1702bc0ba4c08cb9b5304"},"rules":[{"path":"APP.extend_ik_data.slot[0].ik_app[0]","rule":app()}]}));assert_eq!(m.audit["compiled_rules"],0);
}
#[test]
fn encoded_chunked_truncated_and_empty_bodies_do_not_match_plain_body() {
 let m=load(http(json!([head(53,"needle",5)])));
 assert_eq!(matches(&m,b"POST / HTTP/1.1\r\nContent-Length: 6\r\n\r\nneedle"),1);
 for p in [b"POST / HTTP/1.1\r\nContent-Length: 6\r\nContent-Encoding: gzip\r\n\r\nneedle".as_slice(),b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nneedle\r\n0\r\n\r\n",b"POST / HTTP/1.1\r\nContent-Length: 9\r\n\r\nneedle",b"GET /needle HTTP/1.1\r\n\r\n"]{assert_eq!(matches(&m,p),0);}
 let m=load(http(json!([{"index":1,"data":"^$"}])));assert_eq!(matches(&m,b"GET / HTTP/1.1\r\nHost: \r\n\r\n"),0);
}
#[test]
fn negative_regex_offsets_use_bounded_tail_and_literal_escapes() {
 let mut a=app();a["match_method"]=json!(1);a["data"]=json!({"hex":"5e414224"});a["offset"]=json!(-2);
 let m=load(a);assert_eq!(matches(&m,b"xAB"),1);assert_eq!(matches(&m,b"AB"),0);assert_eq!(matches(&m,b"ABx"),0);
 let mut a=app();a["match_method"]=json!(1);a["data"]=json!({"hex":"5e7b5c647d24"});let m=load(a);assert_eq!(matches(&m,b"{d}"),1);assert_eq!(matches(&m,b"{3}"),0);
}
#[test]
fn no_fixed_content_still_enforces_independent_constraints() {
 let mut a=app();a["match_method"]=json!(2);a["port_range"]=json!([{"min_port":80,"max_port":80}]);
 let m=load(a);assert_eq!(matches(&m,b"XY"),1);assert!(m.match_packet(6,1,1,81,b"XY").unwrap().is_empty());
}
#[test]
fn vendor_stacked_quantifiers_are_nested_operators_not_lazy_quantifiers() {
 for (pattern,positive,negative) in [
  ("^live[a-z]+?\\.alicdn\\.com$","live.alicdn.com","live1.alicdn.com"),
  ("^(ab)+?Z$","Z","aZ"),
  ("^a*?b$","b","c"),
 ] {
  let mut a=app();a["data"]=json!(pattern);a["match_method"]=json!(1);let m=load(a);
  assert_eq!(m.audit["compiled_rules"],1);assert_eq!(matches(&m,positive.as_bytes()),1,"{pattern}");assert_eq!(matches(&m,negative.as_bytes()),0,"{pattern}");
 }
}
#[test]
fn tls_selector_two_matches_raw_bytes_with_all_packet_constraints() {
 let mut a=app();a["data"]=json!({"hex":"5e5c7831365c7830332e2e2e5c783031"});a["match_method"]=json!(1);a["https_tls"]=json!(2);a["dir"]=json!(2);
 a["port_range"]=json!([{"min_port":443,"max_port":443}]);a["l7_data_len_range"]=json!([{"min_len":6,"max_len":8}]);
 let m=load(a);let p=b"\x16\x03\x03\x00\x01\x01";
 let h=m.match_packet(6,2,1,443,p).unwrap();assert_eq!(h.len(),1);assert_eq!(h[0].kind,"tls_data");
 assert!(m.match_packet(6,1,1,443,p).unwrap().is_empty());assert!(m.match_packet(6,2,2,443,p).unwrap().is_empty());
 assert!(m.match_packet(6,2,1,80,p).unwrap().is_empty());assert!(m.match_packet(17,2,1,443,p).unwrap().is_empty());
 assert!(m.match_packet(6,2,1,443,&p[..5]).unwrap().is_empty());
}
#[test]
fn repeated_header_conditions_are_all_anded_and_parent_uses_first() {
 let h=http(json!([head(1,"wework",5),head(1,"p.qpic.cn",5)]));
 let m=load(tree(json!({"multifast_happs":[{"index":1,"http_app":[h]}]})));
 assert_eq!(m.audit["compiled_rules"],1);assert_eq!(matches(&m,b"GET / HTTP/1.1\r\nHost: wework.p.qpic.cn\r\n\r\n"),1);
 assert_eq!(matches(&m,b"GET / HTTP/1.1\r\nHost: wework.example\r\n\r\n"),0);
 let h=http(json!([head(1,"image.9game.cn",0),{"index":1,"data":"^http://app.bluestacks.cn"}]));
 let m=load(tree(json!({"exact_host_happs":{"http_app":[h]}})));
 assert_eq!(m.audit["compiled_rules"],1);assert_eq!(matches(&m,b"GET / HTTP/1.1\r\nHost: image.9game.cn\r\n\r\n"),0);
 assert_eq!(matches(&m,b"GET / HTTP/1.1\r\nHost: http://app.bluestacks.cn\r\n\r\n"),0);
}
#[test]
fn inverted_ranges_are_dead_predicates_not_swapped_or_ignored() {
 let mut a=app();a["port_range"]=json!([{"min_port":8410,"max_port":8400}]);let m=load(a.clone());
 assert_eq!(m.audit["compiled_rules"],1);assert_eq!(m.audit["dead_rule_count"],1);
 for port in [0,80,8400,8405,8410,65535]{assert!(m.match_packet(6,1,1,port,b"AB").unwrap().is_empty());}
 a["port_range"]=json!([{"min_port":8410,"max_port":8400},{"min_port":80,"max_port":80}]);let m=load(a);
 assert_eq!(m.audit["dead_rule_count"],0);assert_eq!(matches(&m,b"AB"),1);
}
#[test]
fn subnet_parent_intersects_both_direction_with_original_only_gate() {
 let mut a=app();a["match_method"]=json!(2);a["dir"]=json!(0);a["multi_subnet"]=json!([{"net":0xc6336400_u32,"mask":0xffffff00_u32}]);
 let m=load(tree(json!({"subnet_apps":{"ik_app":[a]}})));let dst=Some("198.51.100.7".parse().unwrap());
 assert_eq!(m.audit["compiled_rules"],1);assert_eq!(m.match_packet_with_dst(6,1,1,80,b"payload",dst).unwrap().len(),1);
 assert!(m.match_packet_with_dst(6,2,1,80,b"payload",dst).unwrap().is_empty());
}
#[test]
fn empty_vendor_regex_preserves_ports_addresses_sequences_and_payload_guard() {
 let mut a=app();a["data"]=json!({"hex":""});a["match_method"]=json!(1);a["port_range"]=json!([{"min_port":443,"max_port":443}]);
 a["multi_dst_addr"]=json!({"ip":[0xc6336407_u32]});let m=load(a);let dst=Some("198.51.100.7".parse().unwrap());
 assert_eq!(m.audit["compiled_rules"],1);assert_eq!(m.match_packet_with_dst(6,1,1,443,b"anything",dst).unwrap().len(),1);
 assert!(m.match_packet_with_dst(6,1,1,80,b"anything",dst).unwrap().is_empty());assert!(m.match_packet_with_dst(6,1,2,443,b"anything",dst).unwrap().is_empty());
 assert!(m.match_packet_with_dst(6,1,1,443,b"anything",None).unwrap().is_empty());assert!(m.match_packet_with_dst(6,1,1,443,b"",dst).unwrap().is_empty());
}
#[test]
fn vendor_nonhex_class_backslashes_do_not_escape_brackets() {
 for (p,yes,no) in [(r"^[^\[]$","a","["),(r"^[^\]]$","a]","a"),(r"^[^\]]$","[]",r"\]")] {
  let mut a=app();a["data"]=json!(p);a["match_method"]=json!(1);let m=load(a);
  assert_eq!(m.audit["compiled_rules"],1);assert_eq!(matches(&m,yes.as_bytes()),1,"{p}");assert_eq!(matches(&m,no.as_bytes()),0,"{p}");
 }
}
