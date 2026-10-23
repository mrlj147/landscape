//! Passive classification only. No routing, packet injection, or kernel mutation.
use crate::{matcher::{Hit, Matcher,decide}, packet::{Capture, Packet}};
use crate::matcher::expect::{ExpectTable,FlowIdentity,PacketState};
use serde_json::{json, Value};
use std::{collections::{HashMap, HashSet}, io::Read, net::IpAddr};

#[derive(Clone, Debug)]
pub struct Cidr { network: IpAddr, prefix: u8 }
impl Cidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (ip, prefix) = s.split_once('/').ok_or("client CIDR requires a prefix")?;
        let network: IpAddr = ip.parse().map_err(|_|"invalid client IP")?;
        let prefix: u8 = prefix.parse().map_err(|_|"invalid prefix")?;
        if prefix > if network.is_ipv4() {32} else {128} { return Err("invalid CIDR prefix".into()); }
        Ok(Self {network, prefix})
    }
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => self.prefix == 0 || (u32::from(a) >> (32-self.prefix)) == (u32::from(b) >> (32-self.prefix)),
            (IpAddr::V6(a), IpAddr::V6(b)) => self.prefix == 0 || (u128::from(a) >> (128-self.prefix)) == (u128::from(b) >> (128-self.prefix)),
            _ => false,
        }
    }
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct Key { client: IpAddr, server: IpAddr, client_port: u16, server_port: u16, protocol: u8 }
impl Key {
    fn json(&self) -> Value { json!({"ip_version":if self.client.is_ipv4(){4}else{6},"protocol":if self.protocol==6{"tcp"}else{"udp"},"src_ip":self.client.to_string(),"src_port":self.client_port,"dst_ip":self.server.to_string(),"dst_port":self.server_port,"direction":"lan_to_wan"}) }
    fn identity(&self)->Option<FlowIdentity>{match (self.client,self.server){(IpAddr::V4(client_ip),IpAddr::V4(server_ip))=>Some(FlowIdentity{client_ip,server_ip,client_port:self.client_port,server_port:self.server_port,protocol:self.protocol}),_=>None}}
}
struct Flow {
    last: f64, counts: [u32;2], initial_seq: [Option<u32>;2], next_seq: [Option<u32>;2], tainted: [bool;2],
    appids: HashSet<u32>, label: Option<Hit>, emitted: Option<f64>, closed: bool, conflicted: bool,
    expectation_source:Option<FlowIdentity>, source_revoked:bool,
}
impl Flow { fn new(now: f64) -> Self { Self {last:now, counts:[0;2], initial_seq:[None;2], next_seq:[None;2], tainted:[false;2], appids:HashSet::new(), label:None, emitted:None, closed:false, conflicted:false,expectation_source:None,source_revoked:false} } }

pub struct Replay<'a> { matcher: &'a Matcher, cidrs: Vec<Cidr>, flows: HashMap<Key,Flow>, max_flows: usize, last_gc: f64, last_packet:Option<f64>, expects:ExpectTable, pub stats: Value }
fn timestamp(now: f64) -> Result<String,String> {
    let secs = now.floor() as i64;
    let nanos = ((now - now.floor()) * 1e9).round().clamp(0.0,999_999_999.0) as u32;
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs,nanos).map(|t|t.to_rfc3339_opts(chrono::SecondsFormat::Millis,true)).ok_or("timestamp out of range".into())
}
fn event(key: &Key, now: f64, kind: &str, hit: &Hit, seq: u32, direction: u8, reason: &str) -> Result<Value,String> {
    Ok(json!({"schema_version":1,"event":kind,"engine_version":env!("CARGO_PKG_VERSION"),"observed_at":timestamp(now)?,"flow":key.json(),"appid":hit.appid,"rule_id":hit.rule_id,"evidence":{"kind":hit.kind,"priority":hit.priority,"arbitration":"unique_highest_numeric_priority","packet_index":seq,"packet_direction":direction,"supported_subset":true,"reason":reason,"transport_start":if key.protocol==6{"observed_syn"}else{"first_observed_datagram"}}}))
}
impl<'a> Replay<'a> {
    pub fn new(matcher: &'a Matcher, cidrs: Vec<Cidr>, max_flows: usize) -> Result<Self,String> {
        if cidrs.is_empty() || max_flows == 0 || max_flows > 65536 { return Err("require client CIDR and 1..65536 max flows".into()); }
        Ok(Self {matcher,cidrs,flows:HashMap::new(),max_flows,last_gc:0.0,last_packet:None,expects:ExpectTable::new(16_384,max_flows),stats:json!({"packets":0,"ignored":0,"tcp_midstream_skipped":0,"gaps_or_overlap":0,"ambiguous_flows":0,"flow_limit_drops":0,"classifications":0,"retractions":0,"expired_flows":0,"max_active_flows":0,"clock_reversals":0,"expectation_learns":0,"expectation_hits":0,"expectation_issues":0,"expectation_source_revocations":0})})
    }
    fn inc(&mut self, key: &str) { let n=self.stats[key].as_u64().unwrap_or(0); self.stats[key]=json!(n+1); }
    fn finish(&mut self, out: Vec<Value>) -> Result<Vec<Value>,String> {
        for e in &out {let k=if e["event"]=="classification"{"classifications"}else{"retractions"};self.inc(k);}
        Ok(out)
    }
    fn invalidate_source(&mut self,key:&Key,now:f64,dir:u8,reason:&str,out:&mut Vec<Value>)->Result<(),String> {
        if let Some(f)=self.flows.get_mut(key){if f.source_revoked{return Ok(());}f.source_revoked=true;}
        if let Some(source)=key.identity() {
            let removed=self.expects.revoke_source(&source);
            if removed>0{self.inc("expectation_source_revocations");}
            for (dependent,f) in &mut self.flows {
                if f.expectation_source.as_ref()==Some(&source) {
                    if let Some(hit)=f.label.take(){out.push(event(dependent,now,"retraction",&hit,0,dir,reason)?);}
                    f.conflicted=true;f.expectation_source=None;
                }
            }
        }
        Ok(())
    }
    fn retract_replaced_source(&mut self,key:&Key,now:f64,dir:u8,out:&mut Vec<Value>)->Result<(),String> {
        // Matcher has already revoked the old actions and may have learned a
        // new winning action. Do not erase that new state a second time.
        if let Some(source)=key.identity() {
            self.inc("expectation_source_revocations");
            for (dependent,f) in &mut self.flows {
                if dependent!=key && f.expectation_source.as_ref()==Some(&source) {
                    if let Some(hit)=f.label.take(){out.push(event(dependent,now,"retraction",&hit,0,dir,"expectation_source_reclassified")?);}
                    f.conflicted=true;f.expectation_source=None;
                }
            }
        }
        Ok(())
    }
    pub fn process(&mut self, now: f64, p: Packet) -> Result<Vec<Value>,String> {
        if !now.is_finite() || now < 0.0 || now > u64::MAX as f64/1000.0 { return Err("invalid packet timestamp".into()); }
        self.inc("packets");
        // The expectation clock is shared across flows, not only within a tuple.
        if self.last_packet.is_some_and(|last|now<last) {self.inc("clock_reversals");return Ok(vec![]);}
        self.last_packet=Some(now);
        let src_local=self.cidrs.iter().any(|c|c.contains(p.src_ip));
        let dst_local=self.cidrs.iter().any(|c|c.contains(p.dst_ip));
        if src_local==dst_local {self.inc("ignored");return Ok(vec![]);}
        let dir=if src_local {1} else {2};let i=(dir-1) as usize;
        let key=if src_local {Key{client:p.src_ip,server:p.dst_ip,client_port:p.src_port,server_port:p.dst_port,protocol:p.protocol}}
            else {Key{client:p.dst_ip,server:p.src_ip,client_port:p.dst_port,server_port:p.src_port,protocol:p.protocol}};
        let mut out=Vec::new();
        let expired:Vec<Key>=if now >= self.last_gc+1.0 {
            self.last_gc=now;
            self.flows.iter().filter(|(_,f)|now-f.last>=120.0).map(|(k,_)|k.clone()).collect()
        }else if self.flows.get(&key).map(|f|now-f.last>=120.0).unwrap_or(false) {vec![key.clone()]}else{vec![]};
        for old_key in expired {
            if let Some(identity)=old_key.identity(){self.expects.revoke_flow(&identity);}
            if let Some(old)=self.flows.remove(&old_key).and_then(|f|f.label) {out.push(event(&old_key,now,"retraction",&old,0,dir,"idle_expiry")?);}
            self.inc("expired_flows");
        }
        if p.protocol==6 && dir==1 && p.syn && !p.ack {
            let reuse=self.flows.get(&key).map(|f|f.closed || f.initial_seq[0]!=p.tcp_seq).unwrap_or(false);
            if reuse {
                if let Some(identity)=key.identity(){self.expects.revoke_flow(&identity);}
                if let Some(old)=self.flows.remove(&key).and_then(|f|f.label) {out.push(event(&key,now,"retraction",&old,0,dir,"tuple_reused")?);}
            }
        }
        if !self.flows.contains_key(&key) {
            if p.protocol==6 && !(dir==1 && p.syn && !p.ack) {self.inc("tcp_midstream_skipped");return self.finish(out);}
            if self.flows.len()>=self.max_flows {self.inc("flow_limit_drops");return self.finish(out);}
            self.flows.insert(key.clone(),Flow::new(now));
            self.stats["max_active_flows"]=json!(self.stats["max_active_flows"].as_u64().unwrap_or(0).max(self.flows.len() as u64));
        }
        let (inspect,unreliable,closed,seq)={
            let f=self.flows.get_mut(&key).unwrap();f.last=now;
            if f.closed{return self.finish(out);}
            if p.rst || p.fin {
                if let Some(hit)=f.label.take(){out.push(event(&key,now,"retraction",&hit,0,dir,"connection_closed")?);}
                f.closed=true;(false,false,true,f.counts[i])
            }else {
                let mut inspect=!p.payload.is_empty() && !f.tainted.iter().any(|x|*x);
                if p.protocol==6 {
                    let packet_seq=p.tcp_seq.ok_or("TCP packet missing sequence")?;
                    if p.syn {
                        if let Some(initial)=f.initial_seq[i] {if initial!=packet_seq {f.tainted[i]=true;}}
                        else {f.initial_seq[i]=Some(packet_seq);f.next_seq[i]=Some(packet_seq.wrapping_add(1));}
                        if !p.payload.is_empty(){f.tainted[i]=true;} // no TCP Fast Open guessing
                        inspect=false;
                    }else if !p.payload.is_empty() {
                        if let Some(expected)=f.next_seq[i] {
                            let delta=packet_seq.wrapping_sub(expected) as i32;
                            if delta<0 && (p.payload.len() as i64)<=-(delta as i64) {inspect=false;}
                            else if delta!=0 {f.tainted[i]=true;inspect=false;self.stats["gaps_or_overlap"]=json!(self.stats["gaps_or_overlap"].as_u64().unwrap_or(0)+1);}
                            else {f.next_seq[i]=Some(packet_seq.wrapping_add(p.payload.len() as u32));}
                        }else {f.tainted[i]=true;inspect=false;}
                    }
                }
                let unreliable=f.tainted.iter().any(|x|*x);
                if unreliable {
                    inspect=false;f.conflicted=true;
                    if let Some(hit)=f.label.take(){out.push(event(&key,now,"retraction",&hit,f.counts[i],dir,"capture_sequence_unreliable")?);}
                }
                if inspect {f.counts[i]=f.counts[i].saturating_add(1);}
                (inspect,unreliable,false,f.counts[i])
            }
        };
        if closed {if let Some(identity)=key.identity(){self.expects.revoke_flow(&identity);}return self.finish(out);}
        if unreliable {self.invalidate_source(&key,now,dir,"expectation_source_unreliable",&mut out)?;return self.finish(out);}
        // A permanently conflicted flow must not keep creating side effects
        // after its own routing label has already been suppressed.
        if self.flows.get(&key).unwrap().conflicted{return self.finish(out);}
        let mut candidates:Vec<(Hit,Option<FlowIdentity>)>=Vec::new();let mut issues=Vec::new();let mut source_replaced=false;
        if let Some(identity)=key.identity() {
            let state=PacketState{flow:identity,direction:dir,now_ms:(now*1000.0).floor() as u64};
            if inspect {
                let incumbent=self.flows.get(&key).and_then(|f|f.label.as_ref());
                let result=self.matcher.match_packet_stateful_with_incumbent(seq,&p.payload,&mut self.expects,&state,incumbent)?;
                source_replaced=result.source_replaced;
                for _ in &result.state_changes{self.inc("expectation_learns");}
                for h in result.hits{candidates.push((h,None));}
                for h in result.expectation_hits {
                    self.inc("expectation_hits");candidates.push((Hit{appid:h.appid,rule_id:h.rule_id,priority:h.priority,kind:"expectation".into()},Some(h.learned_from)));
                }
                issues=result.state_issues;
            }else {
                // SYN/ACK and other payload-free packets establish observations
                // and can match an expectation; packet ordinal need not be 1.
                match self.expects.lookup(&state) {
                    Ok(Some(h))=>{self.inc("expectation_hits");candidates.push((Hit{appid:h.appid,rule_id:h.rule_id,priority:h.priority,kind:"expectation".into()},Some(h.learned_from)));}
                    Ok(None)=>(),Err(e)=>issues.push(e),
                }
            }
        }else if inspect && seq<=7 {
            for hit in self.matcher.match_packet(p.protocol,dir,seq,key.server_port,&p.payload)?{candidates.push((hit,None));}
        }
        if !issues.is_empty() {
            self.inc("expectation_issues");self.stats["last_expectation_issue"]=json!({"flow":key.json(),"issues":issues});
            let f=self.flows.get_mut(&key).unwrap();f.conflicted=true;
            if let Some(hit)=f.label.take(){out.push(event(&key,now,"retraction",&hit,seq,dir,"expectation_state_issue")?);}
            self.invalidate_source(&key,now,dir,"expectation_source_issue",&mut out)?;
            return self.finish(out);
        }
        // Metadata-only EXPECT lookup can also upgrade a previously labelled
        // source. Handle it even when no ordinary signature was inspected.
        let mut contenders=candidates.iter().map(|(h,_)|h.clone()).collect::<Vec<_>>();
        if let Some(old)=&self.flows.get(&key).unwrap().label {contenders.push(old.clone());}
        let pending=decide(&contenders);
        if !source_replaced && self.flows.get(&key).unwrap().label.as_ref().zip(pending.winner.as_ref()).is_some_and(|(old,new)|new.priority>old.priority && new.appid!=old.appid) {
            if let Some(identity)=key.identity(){self.expects.revoke_source(&identity);source_replaced=true;}
        }
        if source_replaced {self.retract_replaced_source(&key,now,dir,&mut out)?;}
        let conflict={
            let f=self.flows.get_mut(&key).unwrap();
            let decision=pending;f.appids=decision.appids.iter().copied().collect();
            if decision.ambiguous {
                if let Some(hit)=f.label.take(){out.push(event(&key,now,"retraction",&hit,seq,dir,"conflicting_application_matches")?);}
                if !f.conflicted {self.stats["ambiguous_flows"]=json!(self.stats["ambiguous_flows"].as_u64().unwrap_or(0)+1);f.conflicted=true;}
                true
            }else {
                if !f.conflicted {if let Some(winner)=decision.winner {
                    let replace=f.label.as_ref().map(|old|winner.priority>old.priority).unwrap_or(true);
                    if replace {
                        if let Some(old)=f.label.take(){out.push(event(&key,now,"retraction",&old,seq,dir,"higher_priority_match")?);}
                        f.expectation_source=candidates.iter().find(|(h,_)|h.rule_id==winner.rule_id && h.appid==winner.appid && h.priority==winner.priority).and_then(|(_,source)|source.clone());
                        f.label=Some(winner);f.emitted=None;
                    }
                }}
                false
            }
        };
        if conflict {self.invalidate_source(&key,now,dir,"expectation_source_conflict",&mut out)?;}
        let f=self.flows.get_mut(&key).unwrap();
        if !f.conflicted {if let Some(hit)=&f.label {
            if f.emitted.map(|t|now-t>=30.0).unwrap_or(true) {
                let mut e=event(&key,now,"classification",hit,seq,dir,if f.emitted.is_none(){"unique_supported_match"}else{"active_flow_refresh"})?;
                e["evidence"]["packet_hits"]=json!(candidates.iter().map(|(h,_)|h).collect::<Vec<_>>());
                out.push(e);f.emitted=Some(now);
            }
        }}
        self.finish(out)
    }
}
pub fn run<R:Read>(capture: &mut Capture<R>, replay: &mut Replay<'_>, mut emit: impl FnMut(Value)->Result<(),String>) -> Result<(),String> {
    while let Some((time,packet))=capture.next_packet()? {if let Some(p)=packet {for e in replay.process(time,p)? {emit(e)?;}}}
    Ok(())
}
