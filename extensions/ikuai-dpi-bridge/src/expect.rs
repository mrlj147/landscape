//! Independently implemented EXPECT state, derived from ik_core 4.0.314.
//!
//! The table never consults a router and has no wall clock. A caller supplies the
//! original (pre-NAT) tuple and a monotonic packet timestamp. Resource refusal is
//! explicit; it never substitutes a broader address or wildcard expectation.
use serde::{Deserialize, Serialize};
use std::{collections::{HashMap,HashSet}, net::Ipv4Addr};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowIdentity {
    pub client_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    pub client_port: u16,
    pub server_port: u16,
    pub protocol: u8,
}
impl FlowIdentity {
    pub fn validate(&self) -> Result<(), String> {
        if ![6,17].contains(&self.protocol) { return Err("EXPECT needs a TCP/UDP original tuple".into()); }
        Ok(())
    }
    fn packet_key(&self, direction:u8) -> (Ipv4Addr,u16,u16) {
        if direction==1 {(self.server_ip,self.client_port,self.server_port)}
        else {(self.client_ip,self.server_port,self.client_port)}
    }
    pub fn packet_destination(&self,direction:u8)->Ipv4Addr {self.packet_key(direction).0}
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketState { pub flow:FlowIdentity, pub direction:u8, pub now_ms:u64 }

/// The baseline only uses after=ANY and count=0. Other values are rejected by
/// the rule compiler rather than silently discarded. Types retain wire values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExpectSpec {
    pub protocol:u8, pub kind:u8, pub age:u8, pub count:u32,
    pub before:bool, pub appid:u32, pub weak:bool, pub timeout_secs:u32,
}
impl ExpectSpec {
    pub fn validate(&self)->Result<(),String> {
        if ![6,17].contains(&self.protocol) || ![1,2,4,8].contains(&self.kind)
            || self.age>7 || self.count!=0 || self.timeout_secs==0 || self.timeout_secs>u32::MAX/250 {
            return Err("unvalidated EXPECT protocol/type/age/count/timeout".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ExpectationHit {pub appid:u32,pub rule_id:u32,pub priority:u32,pub weak:bool,pub kind:u8,pub learned_from:FlowIdentity}
#[derive(Clone, Debug, Serialize)]
pub struct StateChange {pub action:String,pub appid:u32,pub rule_id:u32,pub expires_at_ms:u64}
#[derive(Clone)]
struct Entry {spec:ExpectSpec, source:FlowIdentity, source_rule:u32, ttl_ms:u64, expires:u64, serial:u64}
impl Entry {
    fn matches_key(&self,key:(Ipv4Addr,u16,u16))->bool {
        let (dst,sport,dport)=key;
        match self.spec.kind {
            1=>self.source.client_port==sport,
            2=>self.source.server_ip==dst && self.source.client_port==sport,
            4=>self.source.server_ip==dst && self.source.server_port==dport,
            8=>self.source.server_ip==dst,
            _=>false,
        }
    }
}
#[derive(Default)]
struct Seen {generation:[Option<u64>;2]}

pub struct ExpectTable {
    entries:Vec<Entry>, flows:HashMap<FlowIdentity,Seen>, generations:HashMap<Ipv4Addr,u64>,
    now_ms:Option<u64>, serial:u64, max_entries:usize, max_flows:usize,
    next_expiry_ms:Option<u64>,
}
impl Default for ExpectTable {fn default()->Self {Self::new(16_384,65_536)}}
impl ExpectTable {
    pub fn new(max_entries:usize,max_flows:usize)->Self {
        Self {entries:Vec::new(),flows:HashMap::new(),generations:HashMap::new(),now_ms:None,serial:0,
            max_entries:max_entries.min(1_048_576),max_flows:max_flows.min(1_048_576),next_expiry_ms:None}
    }
    pub fn len(&self)->usize {self.entries.len()}
    pub fn is_empty(&self)->bool {self.entries.is_empty()}
    pub fn flow_count(&self)->usize {self.flows.len()}
    pub fn client_generation_count(&self)->usize {self.generations.len()}
    fn prune_generations(&mut self) {
        let clients=self.flows.keys().map(|f|f.client_ip).chain(self.entries.iter().map(|e|e.source.client_ip)).collect::<HashSet<_>>();
        self.generations.retain(|client,_|clients.contains(client));
    }
    fn clock(&mut self,now_ms:u64)->Result<(),String> {
        if self.now_ms.is_some_and(|old|now_ms<old) {return Err("EXPECT clock moved backwards; reset or start a new replay".into());}
        self.now_ms=Some(now_ms);Ok(())
    }
    pub fn expire(&mut self,now_ms:u64)->Result<usize,String> {
        self.clock(now_ms)?;let before=self.entries.len();
        // Native aging removes on expiry < jiffies, not equality (a3ab-a3af).
        let now_tick_ms=now_ms/4*4;
        if self.next_expiry_ms.is_none_or(|deadline|now_tick_ms<=deadline){return Ok(0);}
        self.entries.retain(|e|e.expires>=now_tick_ms);
        self.next_expiry_ms=self.entries.iter().map(|e|e.expires).min();
        self.prune_generations();
        Ok(before-self.entries.len())
    }
    pub fn clear(&mut self) {self.entries.clear();self.flows.clear();self.generations.clear();self.now_ms=None;self.serial=0;self.next_expiry_ms=None;}
    pub fn revoke_client(&mut self,client:Ipv4Addr)->usize {
        let before=self.entries.len();self.entries.retain(|e|e.source.client_ip!=client);
        self.flows.retain(|f,_|f.client_ip!=client);self.generations.remove(&client);before-self.entries.len()
    }
    /// Remove the connection observation; learning remains valid until explicit
    /// source revocation/expiry, as it is intended to classify other connections.
    pub fn revoke_flow(&mut self,flow:&FlowIdentity)->bool {
        let removed=self.flows.remove(flow).is_some();
        if self.generations.contains_key(&flow.client_ip) && !self.entries.iter().any(|e|e.source.client_ip==flow.client_ip)
            && !self.flows.keys().any(|f|f.client_ip==flow.client_ip) {self.generations.remove(&flow.client_ip);}
        removed
    }
    pub fn revoke_source(&mut self,flow:&FlowIdentity)->usize {
        let before=self.entries.len();self.entries.retain(|e|&e.source!=flow);self.prune_generations();before-self.entries.len()
    }
    pub fn observe(&mut self,state:&PacketState)->Result<(),String> {
        state.flow.validate()?;
        if ![1,2].contains(&state.direction){return Err("invalid EXPECT packet direction".into());}
        self.expire(state.now_ms)?;
        if !self.flows.contains_key(&state.flow) {
            if self.flows.len()>=self.max_flows{return Err("EXPECT flow capacity reached; no state was learned".into());}
            self.flows.insert(state.flow.clone(),Seen::default());
        }
        Ok(())
    }
    /// Apply the native packet-path order: type 1,2,4,8; newest first; remember
    /// the first weak hit but prefer any strong hit. Each direction is checked
    /// once per client generation, including negative observations.
    pub fn lookup(&mut self,state:&PacketState)->Result<Option<ExpectationHit>,String> {
        self.observe(state)?;
        let generation=*self.generations.get(&state.flow.client_ip).unwrap_or(&0);
        let seen=self.flows.get_mut(&state.flow).unwrap();let d=(state.direction-1) as usize;
        if seen.generation[d]==Some(generation){return Ok(None);}
        seen.generation[d]=Some(generation);
        let mut candidates=self.entries.iter().enumerate().filter(|(_,e)|
            e.source.client_ip==state.flow.client_ip && e.spec.protocol==state.flow.protocol && e.matches_key(state.flow.packet_key(state.direction)))
            .map(|(i,e)|(i,e.spec.kind,e.serial,e.spec.weak)).collect::<Vec<_>>();
        candidates.sort_by_key(|(_,kind,serial,_)|(*kind,std::cmp::Reverse(*serial)));
        let picked=candidates.iter().find(|(_,_,_,weak)|!*weak).or(candidates.first()).map(|x|x.0);
        Ok(picked.map(|i| {
            let e=&mut self.entries[i];e.expires=(state.now_ms/4*4).saturating_add(e.ttl_ms);
            ExpectationHit{appid:e.spec.appid,rule_id:e.source_rule,priority:if e.spec.weak{5}else{100},weak:e.spec.weak,kind:e.spec.kind,learned_from:e.source.clone()}
        }))
    }
    /// Calling this twice for the same native key reproduces the observed
    /// refresh branch: age enum in *jiffies*, not the explicit timeout (ad18).
    /// Do not "fix" it to seconds: that would extend classifications beyond
    /// the vendor behavior. The baseline kernel is HZ=250 (acbb).
    pub fn learn(&mut self,spec:&ExpectSpec,rule_id:u32,state:&PacketState)->Result<StateChange,String> {
        spec.validate()?;self.observe(state)?;
        let packet_key=state.flow.packet_key(state.direction);
        if let Some(e)=self.entries.iter_mut().rev().find(|e|e.source.client_ip==state.flow.client_ip
            && e.spec.kind==spec.kind && e.spec.protocol==spec.protocol && e.spec.appid==spec.appid && e.matches_key(packet_key)) {
            e.ttl_ms=spec.age as u64*4;e.expires=(state.now_ms/4*4).saturating_add(e.ttl_ms);
            self.next_expiry_ms=Some(self.next_expiry_ms.map_or(e.expires,|old|old.min(e.expires)));
            return Ok(StateChange{action:"refreshed_native_age_ticks".into(),appid:spec.appid,rule_id,expires_at_ms:e.expires});
        }
        if self.entries.len()>=self.max_entries || self.entries.iter().filter(|e|e.source.client_ip==state.flow.client_ip && e.spec.kind==spec.kind).count()>=512 {
            return Err("EXPECT entry capacity reached; no state was learned".into());
        }
        self.serial=self.serial.checked_add(1).ok_or("EXPECT serial exhausted")?;
        let ttl_ms=spec.timeout_secs as u64*1000;let expires=(state.now_ms/4*4).saturating_add(ttl_ms);
        self.next_expiry_ms=Some(self.next_expiry_ms.map_or(expires,|old|old.min(expires)));
        self.entries.push(Entry{spec:spec.clone(),source:state.flow.clone(),source_rule:rule_id,ttl_ms,expires,serial:self.serial});
        if spec.before {*self.generations.entry(state.flow.client_ip).or_default()+=1;}
        Ok(StateChange{action:"learned".into(),appid:spec.appid,rule_id,expires_at_ms:expires})
    }
}
