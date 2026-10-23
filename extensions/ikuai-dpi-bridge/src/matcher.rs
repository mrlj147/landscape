use regex::bytes::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::{BTreeMap, HashSet}, fs, net::Ipv4Addr, path::Path};

#[path = "expect.rs"]
pub mod expect;
use expect::{ExpectSpec,ExpectTable,PacketState,ExpectationHit,StateChange};
const SEMANTICS_PROFILE: &str = "ikuai-4.0.314-static-v4";

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 || s.len() > 131072 { return Err("invalid/bounded hex length".into()); }
    s.as_bytes().chunks_exact(2).map(|p| {
        let h = (p[0] as char).to_digit(16).ok_or("invalid hex")?;
        let l = (p[1] as char).to_digit(16).ok_or("invalid hex")?;
        Ok(((h << 4) | l) as u8)
    }).collect()
}
fn num(v: &Value, key: &str, default: u64) -> u64 {
    v.get(key).and_then(|x| x.as_u64().or_else(|| x.get("number").and_then(Value::as_u64))).unwrap_or(default)
}
fn checked_num(v: &Value, key: &str, default: Option<u64>) -> Result<u64,String> {
    match v.get(key) {
        None => default.ok_or_else(||format!("missing {key}")),
        Some(x) => {
            if x.is_object() { allowed(x,&["number","name"])?; }
            x.as_u64().or_else(||x.get("number").and_then(Value::as_u64))
                .ok_or_else(||format!("invalid unsigned value: {key}"))
        }
    }
}
fn allowed(v: &Value, keys: &[&str]) -> Result<(), String> {
    for k in v.as_object().ok_or("expected object")?.keys() {
        if !keys.contains(&k.as_str()) { return Err(format!("unsupported condition: {k}")); }
    }
    Ok(())
}
fn data(v: &Value) -> Result<Vec<u8>, String> {
    if let Some(s) = v.as_str() { Ok(s.as_bytes().to_vec()) }
    else { unhex(v.get("hex").and_then(Value::as_str).ok_or("missing byte data")?) }
}

/// Translate only the statically checked vendor byte-regex grammar. In
/// particular, never reinterpret vendor literal escapes as Rust character classes.
fn vendor_regex(bytes:&[u8]) -> Result<String,String> {
    // regcomp -> add_selfloop_long transforms even an empty input into ".*".
    if bytes.is_empty(){return Ok(".*".into());}
    let mut out=String::new();let mut i=0;let mut class=false;let mut class_first=false;
    let mut atom_start=None;let mut groups=Vec::new();let mut class_start=0;
    while i<bytes.len() {
        let c=bytes[i];
        if c==0 {return Err("NUL in vendor C-string pattern is unsupported".into());}
        if c==b'\\' {
            if !class {atom_start=Some(out.len());}
            let n=*bytes.get(i+1).ok_or("trailing regex escape")?;
            if n==b'x' {
                let h=*bytes.get(i+2).ok_or("short hex escape")?;
                let l=*bytes.get(i+3).ok_or("short hex escape")?;
                if !h.is_ascii_hexdigit() || !l.is_ascii_hexdigit(){return Err("invalid hex escape".into());}
                out.push_str(&format!("\\x{}{}",h as char,l as char));i+=4;
            } else if !class {
                out.push_str(&format!("\\x{n:02x}"));i+=2;
            } else {
                // In byte classes only xHH is an escape. Other backslashes are
                // themselves class members; the next byte is parsed normally.
                out.push_str("\\x5c");i+=1;
            }
            class_first=false;continue;
        }
        if class {
            match c {
                b']' if !class_first => {out.push(']');class=false;atom_start=Some(class_start);}
                b'^' if class_first => out.push('^'),
                b'-' => out.push('-'),
                b'[' => out.push_str("\\x5b"),
                b']' => return Err("empty byte class unsupported".into()),
                _ => out.push_str(&format!("\\x{c:02x}")),
            }
            class_first=false;i+=1;continue;
        }
        match c {
            b'[' => {class_start=out.len();class=true;class_first=true;out.push('[');}
            b']' => {atom_start=Some(out.len());out.push_str("\\x5d");}
            b'(' if bytes.get(i+1)==Some(&b'?') => return Err("regex extensions unsupported".into()),
            b'(' => {groups.push(out.len());out.push('(');atom_start=None;}
            b')' => {let start=groups.pop().ok_or("unbalanced regex close")?;out.push(')');atom_start=Some(start);}
            b'|' => {out.push('|');atom_start=None;}
            b'.' => {atom_start=Some(out.len());out.push('.');}
            b'^' => {atom_start=Some(out.len());out.push_str("\\A");}
            b'$' => {atom_start=Some(out.len());out.push_str("\\z");}
            b'*' | b'+' | b'?' => {
                // re2post emits each postfix operator; post2nfa transforms the
                // previous fragment again. a+? means (a+)?, never lazy a+.
                let start=atom_start.ok_or("quantifier without atom")?;
                out.insert_str(start,"(?:");out.push(')');out.push(c as char);i+=1;continue;
            }
            _ => {atom_start=Some(out.len());out.push_str(&format!("\\x{c:02x}"));}
        }
        i+=1;
    }
    if class || !groups.is_empty(){return Err("unterminated byte class/group".into());}
    Ok(out)
}

#[derive(Debug)]
enum Pattern { Literal(Vec<u8>), Regex(Regex), Prefix(Vec<u8>), Exact(Vec<u8>) }
impl Pattern {
    fn compile(bytes: Vec<u8>, method: u64) -> Result<Self, String> {
        if (bytes.is_empty() && ![0,1].contains(&method)) || bytes.len() > 4096 { return Err("empty/oversize pattern".into()); }
        match method {
            5 => Ok(Self::Literal(bytes)),
            0 => Ok(Self::Prefix(bytes)),
            1 => {
                let pattern=vendor_regex(&bytes)?;
                RegexBuilder::new(&pattern).unicode(false).dot_matches_new_line(true).size_limit(256 * 1024)
                    .dfa_size_limit(256 * 1024).build().map(Self::Regex)
                    .map_err(|e| format!("unsupported byte regex: {e}"))
            }
            _ => Err(format!("unsupported matching method: {method}")),
        }
    }
    fn matches(&self, hay: &[u8]) -> bool {
        match self {
            Self::Literal(b) => hay.windows(b.len()).any(|s| s == b),
            Self::Prefix(b) => hay.starts_with(b),
            Self::Exact(b) => hay==b,
            Self::Regex(r) => r.is_match(hay),
        }
    }
}

#[derive(Debug)]
enum Target { Payload(Pattern), TlsData(Pattern), Sni(Pattern), Http(Vec<(u64, Pattern)>), Metadata }
#[derive(Debug,Default)]
struct Container {
    slot:Option<(usize,usize)>, payload_prefix:Option<Vec<u8>>,
    original_only:bool,
    header_prefix:Option<(u64,Vec<u8>)>, header_suffix:Option<(u64,Vec<u8>)>, header_exact:Option<(u64,Vec<u8>)>,
}
#[derive(Debug)]
struct Rule {
    appid: u32, id: u32, direction: u8, proto: u8, sequences: Vec<u32>,
    ports: Vec<(u16,u16)>, lengths: Vec<(usize,usize)>, priority: u32, target: Target,
    offset:i32, destinations:Option<Vec<u32>>, subnets:Option<Vec<(u32,u32)>>, container:Container,
    expect:Option<ExpectSpec>, dead_reasons:Vec<String>,
}
#[derive(Serialize, Clone, Debug)]
pub struct Hit { pub appid: u32, pub rule_id: u32, pub priority: u32, pub kind: String }
#[derive(Serialize,Clone,Debug)]
pub struct Decision {pub priority:Option<u32>,pub appids:Vec<u32>,pub winner:Option<Hit>,pub ambiguous:bool}
/// Portable arbitration, explicitly not native force/first-hit order: only a
/// unique application at the highest numeric priority may produce a label.
pub fn decide(hits:&[Hit])->Decision {
    let priority=hits.iter().map(|h|h.priority).max();let mut appids=hits.iter().filter(|h|Some(h.priority)==priority).map(|h|h.appid).collect::<Vec<_>>();
    appids.sort_unstable();appids.dedup();let ambiguous=appids.len()>1;
    let winner=if appids.len()==1{hits.iter().filter(|h|Some(h.priority)==priority).min_by_key(|h|h.rule_id).cloned()}else{None};
    Decision{priority,appids,winner,ambiguous}
}
#[derive(Deserialize, Debug)]
pub struct Context {
    pub protocol: u8,
    pub direction: u8,
    pub packet_index: u32,
    pub server_port: u16,
    pub payload_hex: String,
    #[serde(default)]
    pub dst_ip:Option<String>,
}
pub struct Matcher { rules: Vec<Rule>, pub audit: Value }
#[derive(Serialize,Debug)]
pub struct StatefulResult {
    pub hits:Vec<Hit>,pub expectation_hits:Vec<ExpectationHit>,pub state_changes:Vec<StateChange>,pub state_issues:Vec<String>,
    pub decision:Decision,pub source_replaced:bool,
}

fn collect<'a>(v: &'a Value, path: String, out: &mut Vec<(String,&'a Value)>) {
    match v {
        Value::Object(o) => {
            if let (Some(source),Some(rule))=(o.get("path").and_then(Value::as_str),o.get("rule")) {
                if matches!(rule.get("_type").and_then(Value::as_str),Some("IK_APP"|"IK_HTTP_APP")) {
                    out.push((source.to_string(),rule));return;
                }
            }
            if matches!(o.get("_type").and_then(Value::as_str), Some("IK_APP" | "IK_HTTP_APP")) {
                out.push((path.clone(),v));
            }
            for (k,val) in o { if val.is_object() || val.is_array() { collect(val,format!("{path}.{k}"),out); } }
        }
        Value::Array(a) => for (i,val) in a.iter().enumerate() { collect(val,format!("{path}[{i}]"),out); },
        _ => (),
    }
}
fn ranges(v:&Value,key:&str,min:&str,max:&str,bound:u64) -> Result<Vec<(u64,u64)>,String> {
    let mut out=Vec::new();
    if let Some(a)=v.get(key) {
        for item in a.as_array().ok_or("invalid range list")? {
            allowed(item,&["_type",min,max])?;
            let lo=item[min].as_u64().ok_or("missing lower range")?;
            let hi=item[max].as_u64().ok_or("missing upper range")?;
            if hi>bound || lo>bound { return Err("invalid range bounds".into()); }
            out.push((lo,hi));
        }
    }
    Ok(out)
}
fn index_tail<'a>(s:&'a str,prefix:&str)->Option<(usize,&'a str)> {
    let s=s.strip_prefix(prefix)?;let (number,tail)=s.split_once(']')?;
    Some((number.parse().ok()?,tail))
}
fn leaf(s:&str,prefix:&str)->bool {
    index_tail(s,prefix).map(|(_,tail)|tail.is_empty()).unwrap_or(false)
}
fn raw_prefix(mut bytes:Vec<u8>,n:usize)->Result<Vec<u8>,String> {
    // Native prefix tables skip a literal leading '^' before hashing raw bytes.
    if bytes.first()==Some(&b'^'){bytes.remove(0);}
    if bytes.len()<n{return Err("pattern shorter than container prefix".into());}
    bytes.truncate(n);Ok(bytes)
}
fn header_pattern(v:&Value,index:u64)->Result<Vec<u8>,String> {
    let hs=v["http_info"]["header"].as_array().ok_or("missing headers")?;
    let found=hs.iter().filter(|h|num(h,"index",u64::MAX)==index).collect::<Vec<_>>();
    if found.is_empty(){return Err("container header absent".into());}
    data(&found[0]["data"])
}
fn container(path:&str,v:&Value,root:Option<&Value>)->Result<Container,String> {
    if path=="root" || leaf(path,"root["){return Ok(Container::default());}
    let d=root.ok_or("source tree required: flattened vendor rules lack parent metadata")?
        .get("extend_ik_data").ok_or("missing extended rule tree")?;
    allowed(d,&["_type","slot","http_app","dst_match_hcnt","dst_apps","subnet_match_hcnt","subnet_apps","seq_len_match_hcnt","seq_len_apps","exact_host_hcnt","exact_host_happs","prefix_match_happs","one_header_happs","postfix_match_happs","prefix_match_apps","multifast_happs"])?;
    let p=path.strip_prefix("APP.extend_ik_data.").ok_or("unknown rule container")?;
    let mut c=Container::default();
    if let Some((slot,tail))=index_tail(p,"slot[") {
        let slots=d["slot"].as_array().ok_or("missing slots")?;
        if slots.is_empty() || slots.len()>65536 || slot>=slots.len() || !(leaf(tail,".ik_app[") || leaf(tail,".multi_str_apps.ik_app[")) {return Err("unknown slot container".into());}
        allowed(&slots[slot],&["_type","ik_app","multi_str_apps"])?;
        if v["_type"]!="IK_APP"{return Err("wrong type in slot".into());}
        if tail.starts_with(".multi_str_apps") {
            allowed(&slots[slot]["multi_str_apps"],&["_type","ik_app"])?;
            if ![0,5].contains(&checked_num(v,"match_method",Some(0))?){return Err("multistring container requires literal predicate".into());}
        }
        if slot!=0{c.slot=Some((slots.len(),slot));}return Ok(c);
    }
    for (name,required) in [("dst_apps","multi_dst_addr"),("subnet_apps","multi_subnet")] {
        if leaf(p,&format!("{name}.ik_app[")) {
            allowed(&d[name],&["_type","ik_app"])?;
            if v.get(required).is_none() {return Err("destination container constraint missing".into());}
            c.original_only=true;
            return Ok(c);
        }
    }
    if leaf(p,"seq_len_apps.ik_app[") {
        allowed(&d["seq_len_apps"],&["_type","ik_app"])?;
        let ls=v["l7_data_len_range"].as_array().ok_or("sequence/length container constraint missing")?;
        if num(v,"pkt_seq",0)==0 || ls.len()!=1 || ls[0]["min_len"]!=ls[0]["max_len"] {return Err("unvalidated sequence/length group shape".into());}
        return Ok(c);
    }
    if let Some((group,tail))=index_tail(p,"prefix_match_apps[") {
        if !leaf(tail,".apps.ik_app["){return Err("unknown APP prefix container".into());}
        let g=d["prefix_match_apps"].get(group).ok_or("missing APP prefix parent")?;
        allowed(g,&["_type","offset","hslot_cnt","apps"])?;allowed(&g["apps"],&["_type","ik_app"])?;
        let n=checked_num(g,"offset",None)?;if n==0 || n>4096{return Err("invalid parent prefix length".into());}
        c.payload_prefix=Some(raw_prefix(data(&v["data"])?,n as usize)?);return Ok(c);
    }
    for (name,suffix) in [("prefix_match_happs",false),("postfix_match_happs",true)] {
        if let Some((group,tail))=index_tail(p,&format!("{name}[")) {
            if !leaf(tail,".happs.http_app["){return Err("unknown HTTP offset container".into());}
            let g=d[name].get(group).ok_or("missing HTTP offset parent")?;
            allowed(g,&["_type","index","offset","hslot_cnt","happs"])?;allowed(&g["happs"],&["_type","http_app"])?;
            let index=checked_num(g,"index",None)?;let n=checked_num(g,"offset",None)?;
            if index>57 || n==0 || n>4096{return Err("invalid HTTP parent index/length".into());}
            let mut bytes=header_pattern(v,index)?;
            if suffix {
                if bytes.last()==Some(&b'$'){bytes.pop();}
                if bytes.len()<n as usize{return Err("pattern shorter than parent suffix".into());}
                c.header_suffix=Some((index,bytes[bytes.len()-n as usize..].to_vec()));
            }else{c.header_prefix=Some((index,raw_prefix(bytes,n as usize)?));}
            return Ok(c);
        }
    }
    if leaf(p,"exact_host_happs.http_app[") {
        allowed(&d["exact_host_happs"],&["_type","http_app"])?;
        c.header_exact=Some((1,header_pattern(v,1)?));return Ok(c);
    }
    for name in ["one_header_happs","multifast_happs"] {
        if let Some((group,tail))=index_tail(p,&format!("{name}[")) {
            let g=d[name].get(group).ok_or("missing HTTP group parent")?;
            let index=checked_num(g,"index",None)?;if index>57{return Err("invalid HTTP parent index".into());}
            if name=="one_header_happs" {
                allowed(g,&["_type","index","happs"])?;allowed(&g["happs"],&["_type","http_app"])?;
                if !leaf(tail,".happs.http_app["){return Err("unknown one-header container".into());}
            }else {
                allowed(g,&["_type","index","http_app"])?;
                if !leaf(tail,".http_app["){return Err("unknown multifast container".into());}
                let hs=v["http_info"]["header"].as_array().ok_or("missing headers")?;
                let h=hs.iter().find(|h|num(h,"index",u64::MAX)==index).ok_or("missing multifast parent header")?;
                if ![0,4,5].contains(&checked_num(h,"match_method",None)?){return Err("multifast requires literal parent header".into());}
            }
            header_pattern(v,index)?;return Ok(c);
        }
    }
    if leaf(p,"http_app["){return Ok(c);}
    Err("unknown rule container".into())
}
fn compile(v: &Value,path:&str,root:Option<&Value>) -> Result<Rule,String> {
    let http=v["_type"]=="IK_HTTP_APP";
    if http {allowed(v,&["_type","appid","rule_id","priority","dir","pkt_seq","http_info","match_flag"])?;}
    else {allowed(v,&["_type","appid","rule_id","priority","dir","pkt_seq","proto","data","match_method","port_range","l7_data_len_range","multi_seq","https_tls","offset","multi_dst_addr","multi_subnet","match_flag","expect_conn"])?;}
    let offset=match v.get("offset") {
        None=>0,Some(x)=>x.as_i64().filter(|n|(-16384..=16384).contains(n)).ok_or("invalid/oversize offset unsupported")? as i32
    };
    if checked_num(v,"match_flag",Some(0))?!=0{return Err("nondefault match flag unsupported".into());}
    let appid=u32::try_from(checked_num(v,"appid",None)?).map_err(|_|"invalid appid")?;
    let id=u32::try_from(checked_num(v,"rule_id",Some(0))?).map_err(|_|"invalid rule id")?;
    let direction=checked_num(v,"dir",None)?;
    if direction>2 { return Err("unknown direction".into()); }
    let proto=if http {6} else {checked_num(v,"proto",None)?};
    if ![0,6,17].contains(&proto) { return Err("unknown protocol".into()); }
    let seq=checked_num(v,"pkt_seq",None)?;
    if seq>7 { return Err("packet sequence outside supported 0..7".into()); }
    let mut sequences=if seq==0 {Vec::new()} else {vec![seq as u32]};
    if let Some(m)=v.get("multi_seq") {
        allowed(m,&["_type","pkt_seq"])?;
        let multi:Vec<u32>=m["pkt_seq"].as_array().ok_or("invalid multi sequence")?.iter()
            .map(|x| x.as_u64().filter(|n| *n>0 && *n<=7).map(|n|n as u32).ok_or("invalid sequence".to_string())).collect::<Result<_,_>>()?;
        if multi.is_empty() { return Err("empty multi sequence".into()); }
        if seq==0{sequences=multi;}else if !multi.contains(&(seq as u32)){return Err("single/multi sequence intersection empty".into());}
    }
    let ports:Vec<_>=ranges(v,"port_range","min_port","max_port",65535)?.into_iter().map(|(a,b)|(a as u16,b as u16)).collect();
    let lengths:Vec<_>=ranges(v,"l7_data_len_range","min_len","max_len",65535)?.into_iter().map(|(a,b)|(a as usize,b as usize)).collect();
    let mut dead_reasons=Vec::new();
    if !ports.is_empty() && ports.iter().all(|(a,b)|a>b){dead_reasons.push("all port intervals are empty (lower > upper)".into());}
    if !lengths.is_empty() && lengths.iter().all(|(a,b)|a>b){dead_reasons.push("all length intervals are empty (lower > upper)".into());}
    let expect=v.get("expect_conn").map(|e| {
        allowed(e,&["_type","proto","type","age","count","after","before","app_id","match_flag","timeout"])?;
        if checked_num(e,"after",None)?!=0{return Err("EXPECT after other than ANY not validated".into());}
        let flag=checked_num(e,"match_flag",Some(0))?;
        if flag>1{return Err("EXPECT unknown match flags".into());}
        let spec=ExpectSpec{
            protocol:u8::try_from(checked_num(e,"proto",None)?).map_err(|_|"EXPECT invalid protocol")?,
            kind:u8::try_from(checked_num(e,"type",None)?).map_err(|_|"EXPECT invalid type")?,
            age:u8::try_from(checked_num(e,"age",None)?).map_err(|_|"EXPECT invalid age")?,
            count:u32::try_from(checked_num(e,"count",None)?).map_err(|_|"EXPECT invalid count")?,
            before:e["before"].as_bool().ok_or("EXPECT before must be boolean")?,
            appid:u32::try_from(checked_num(e,"app_id",None)?).map_err(|_|"EXPECT invalid appid")?,weak:flag==1,
            timeout_secs:u32::try_from(checked_num(e,"timeout",None)?).map_err(|_|"EXPECT invalid timeout")?,
        };spec.validate()?;Ok::<_,String>(spec)
    }).transpose()?;
    let destinations=if let Some(m)=v.get("multi_dst_addr") {
        allowed(m,&["_type","ip"])?;
        let xs=m["ip"].as_array().ok_or("invalid destination list")?;
        if xs.is_empty(){return Err("empty destination list".into());}
        Some(xs.iter().map(|x|x.as_u64().and_then(|n|u32::try_from(n).ok()).ok_or("invalid destination IPv4".to_string())).collect::<Result<Vec<_>,_>>()?)
    }else{None};
    let subnets=if let Some(a)=v.get("multi_subnet") {
        let mut ns=Vec::new();for m in a.as_array().ok_or("invalid subnet list")? {
            allowed(m,&["_type","net","mask"])?;
            let net=u32::try_from(checked_num(m,"net",None)?).map_err(|_|"invalid IPv4 subnet")?;
            let mask=u32::try_from(checked_num(m,"mask",None)?).map_err(|_|"invalid IPv4 mask")?;
            ns.push((net,mask));
        }
        if ns.is_empty(){return Err("empty subnet list".into());}Some(ns)
    }else{None};
    if offset<0 && ![1,5].contains(&checked_num(v,"match_method",Some(0))?) {return Err("negative offset supported only for regex/substring".into());}
    let target=if http {
        allowed(&v["http_info"],&["_type","header"])?;
        let mut hs=Vec::new();
        for h in v["http_info"]["header"].as_array().ok_or("missing HTTP headers")? {
            allowed(h,&["_type","data","index","match_method"])?;
            let index=checked_num(h,"index",None)?;
            if index>57 { return Err(format!("unknown HTTP index {index}")); }
            let bytes=data(&h["data"])?;
            let pattern=match h.get("match_method") {
                None=>Pattern::compile(bytes,1)?,
                Some(_)=>match checked_num(h,"match_method",None)? {
                    0 if !bytes.is_empty()=>Pattern::Exact(bytes),
                    4=>Pattern::compile(bytes,0)?,
                    5=>Pattern::compile(bytes,5)?,
                    _=>return Err("unsupported explicit HTTP matching method".into()),
                }
            };
            hs.push((index,pattern));
        }
        if hs.is_empty() { return Err("empty HTTP conditions".into()); }
        for (index,p) in &hs {
            if let Pattern::Exact(value)=p {
                if hs.iter().any(|(other,q)|other==index && !q.matches(value)) {
                    dead_reasons.push("HTTP AND predicates contradict an exact value".into());break;
                }
            }
        }
        Target::Http(hs)
    } else {
        let method=checked_num(v,"match_method",Some(0))?;
        if method==2 {
            if checked_num(v,"https_tls",Some(0))?!=0{return Err("unvalidated NO_FIXED TLS variant".into());}
            data(&v["data"])?; // Native method2 does not evaluate the stored content bytes.
            Target::Metadata
        }else{
        let pat=Pattern::compile(data(&v["data"])?,method)?;
        match checked_num(v,"https_tls",Some(0))? {
            0 => Target::Payload(pat),
            1 => Target::Sni(pat),
            2 => Target::TlsData(pat),
            n => return Err(format!("TLS selector {n} unsupported")),
        }}
    };
    let priority=u32::try_from(checked_num(v,"priority",Some(if http{105}else{5}))?).map_err(|_|"invalid priority")?;
    if priority>255{return Err("priority outside native byte range".into());}
    let container=container(path,v,root)?;
    if container.original_only && direction==2{dead_reasons.push("original-only parent conflicts with reply-only rule".into());}
    Ok(Rule{appid,id,direction:direction as u8,proto:proto as u8,sequences,ports,lengths,priority,target,offset,destinations,subnets,container,expect,dead_reasons})
}

impl Matcher {
    pub fn load(path:&Path,appids:&HashSet<u32>) -> Result<Self,String> {
        Self::load_filtered(path,appids,&HashSet::new())
    }
    pub fn load_filtered(path:&Path,appids:&HashSet<u32>,rule_ids:&HashSet<u32>) -> Result<Self,String> {
        if fs::metadata(path).map_err(|e|e.to_string())?.len()>64*1024*1024 { return Err("rule file exceeds 64 MiB".into()); }
        let v:Value=serde_json::from_slice(&fs::read(path).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
        let source_tree=if v["data"]["_type"]=="APP" {Some(&v["data"])} else if v["_type"]=="APP" {Some(&v)} else {None};
        let mut records=Vec::new();
        if v["data"]["_type"]=="APP" {collect(&v["data"],"APP".into(),&mut records);}
        else {collect(&v,if v["_type"]=="APP"{"APP".into()}else{"root".into()},&mut records);}
        let mut rules=Vec::new();let mut skipped=Vec::new();let mut totals=BTreeMap::<u32,(usize,usize)>::new();
        let mut seen=HashSet::new();let mut selected=0;
        for (path,r) in &records {
            let id=num(r,"appid",u64::MAX) as u32;
            if !appids.is_empty() && !appids.contains(&id) {continue;}
            if !rule_ids.is_empty() && !rule_ids.contains(&(num(r,"rule_id",u64::MAX) as u32)){continue;}
            selected+=1;totals.entry(id).or_default().0+=1;
            if !seen.insert((path.clone(),serde_json::to_string(r).unwrap())) {continue;}
            match compile(r,path,source_tree) {
                Ok(rule)=>{totals.entry(id).or_default().1+=1;rules.push(rule);}
                Err(reason)=>skipped.push(json!({"appid":id,"rule_id":num(r,"rule_id",0),"path":path,"reason":reason})),
            }
        }
        if records.is_empty(){return Err("no typed application rules found".into());}
        let dead=rules.iter().filter(|r|!r.dead_reasons.is_empty()).map(|r|json!({"appid":r.appid,"rule_id":r.id,"reasons":r.dead_reasons})).collect::<Vec<_>>();
        let stateful=rules.iter().filter(|r|r.expect.is_some()).count();
        let audit=json!({"schema_version":1,"engine_version":env!("CARGO_PKG_VERSION"),"mode":"conservative_stateful","arbitration_policy":"unique highest numeric priority; same-priority different appids refuse; not vendor force order","source_container_profile_recognized":source_tree.is_some(),"semantics_profile":SEMANTICS_PROFILE,"input_records":records.len(),"selected_records":selected,"compiled_rules":rules.len(),"stateful_rules":stateful,"dead_rule_count":dead.len(),"dead_rules":dead,"by_appid":totals,"skipped":skipped,"limits":{"max_inspected_payload":16384,"max_payload_packets_per_direction":7},"runtime_restrictions":["EXPECT requires original tuple and monotonic timestamp; ambiguous actions are not learned", "complete TCP ClientHello SNI only; no QUIC/ECH", "complete HTTP header block required; reject folded/duplicate fields", "HTTP body absent for encoded/chunked/truncated bodies", "conservative parent literal gates exclude native hash-collision candidates"],"not_claimed":["vendor engine equivalence","live accuracy","gigabit throughput","automatic WAN selection","vendor priority-100/200 force order, equal-priority global order and arbitrary conntrack cache behavior","cryptographic authentication of edited JSON rules"],"container_policy":"derive constraints from full input parent metadata; preserve slot and conservative literal prefix/suffix/exact prefilters; no app.dat hash allowlist"});
        Ok(Self{rules,audit})
    }
    pub fn evaluate(&self,ctx:&Context) -> Result<Vec<Hit>,String> {
        let payload=unhex(&ctx.payload_hex)?;
        let dst=ctx.dst_ip.as_ref().map(|s|s.parse::<Ipv4Addr>().map_err(|_|"invalid destination IPv4")).transpose()?;
        self.match_packet_with_dst(ctx.protocol,ctx.direction,ctx.packet_index,ctx.server_port,&payload,dst)
    }
    pub fn match_packet(&self,proto:u8,dir:u8,seq:u32,port:u16,payload:&[u8]) -> Result<Vec<Hit>,String> {
        self.match_packet_with_dst(proto,dir,seq,port,payload,None)
    }
    pub fn match_packet_with_dst(&self,proto:u8,dir:u8,seq:u32,port:u16,payload:&[u8],dst:Option<Ipv4Addr>) -> Result<Vec<Hit>,String> {
        self.match_inner(proto,dir,seq,port,payload,dst,false,None)
    }
    pub fn evaluate_stateful(&self,ctx:&Context,table:&mut ExpectTable,state:&PacketState)->Result<StatefulResult,String> {
        if ctx.protocol!=state.flow.protocol || ctx.direction!=state.direction || ctx.server_port!=state.flow.server_port {
            return Err("packet context and original EXPECT tuple disagree".into());
        }
        if let Some(dst)=&ctx.dst_ip {
            if dst.parse::<Ipv4Addr>().map_err(|_|"invalid destination IPv4")?!=state.flow.packet_destination(state.direction){return Err("packet destination and original EXPECT tuple disagree".into());}
        }
        let payload=unhex(&ctx.payload_hex)?;
        self.match_packet_stateful(ctx.packet_index,&payload,table,state)
    }
    /// Stateful evaluation is explicit: stateless entry points never emit an
    /// EXPECT signature while silently omitting its cross-connection action.
    pub fn match_packet_stateful(&self,seq:u32,payload:&[u8],table:&mut ExpectTable,state:&PacketState)->Result<StatefulResult,String> {
        self.match_packet_stateful_with_incumbent(seq,payload,table,state,None)
    }
    pub fn match_packet_stateful_with_incumbent(&self,seq:u32,payload:&[u8],table:&mut ExpectTable,state:&PacketState,incumbent:Option<&Hit>)->Result<StatefulResult,String> {
        state.flow.validate()?;
        if ![1,2].contains(&state.direction) || seq==0{return Err("invalid stateful packet context".into());}
        let mut expectation_hits=Vec::new();
        if let Some(hit)=table.lookup(state)?{expectation_hits.push(hit);}
        let mut matched_indices=Vec::new();
        let hits=self.match_inner(state.flow.protocol,state.direction,seq,state.flow.server_port,payload,Some(state.flow.packet_destination(state.direction)),true,Some(&mut matched_indices))?;
        let mut all_hits=hits.clone();
        all_hits.extend(expectation_hits.iter().map(|h|Hit{appid:h.appid,rule_id:h.rule_id,priority:h.priority,kind:"expectation".into()}));
        if let Some(hit)=incumbent{all_hits.push(hit.clone());}
        let decision=decide(&all_hits);
        // A stronger, different application invalidates learning performed by
        // the former label. Revoke before applying the new winning action.
        let source_replaced=incumbent.zip(decision.winner.as_ref()).is_some_and(|(old,new)|new.priority>old.priority && new.appid!=old.appid);
        if source_replaced {table.revoke_source(&state.flow);}
        matched_indices.retain(|&i|Some(self.rules[i].priority)==decision.priority);
        let mut actions=Vec::new();
        for &i in &matched_indices {
            let r=&self.rules[i];if let Some(spec)=&r.expect {actions.push((r.id,r.appid,spec));}
        }
        let mut state_changes=Vec::new();let mut state_issues=Vec::new();
        if let Some((id,appid,spec))=actions.first() {
            // Applying every candidate's side effect would make false learning
            // persistent. Until native first-hit ordering is reproduced, only
            // an unambiguous candidate action is allowed to create state.
            if decision.ambiguous || decision.appids.first()!=Some(appid) || matched_indices.iter().any(|&i|self.rules[i].expect.as_ref()!=Some(*spec)) {
                state_issues.push("ambiguous_expect_action: candidates disagree; nothing learned".into());
            }else {
                match table.learn(spec,*id,state) {Ok(change)=>state_changes.push(change),Err(e)=>state_issues.push(e)}
            }
        }
        Ok(StatefulResult{hits,expectation_hits,state_changes,state_issues,decision,source_replaced})
    }
    fn match_inner(&self,proto:u8,dir:u8,seq:u32,port:u16,payload:&[u8],dst:Option<Ipv4Addr>,stateful:bool,mut matched_indices:Option<&mut Vec<usize>>) -> Result<Vec<Hit>,String> {
        if ![6,17].contains(&proto) || ![1,2].contains(&dir) || seq==0 {return Err("invalid packet context".into());}
        if payload.is_empty() || payload.len()>16384 || seq>7 {return Ok(Vec::new());}
        let sni=if proto==6 {tls_sni(payload)} else {None};
        let headers=if proto==6 {http_headers(payload)} else {None};
        let mut out=Vec::new();
        for (index,r) in self.rules.iter().enumerate() {
            if !r.dead_reasons.is_empty() || r.expect.is_some() && !stateful || r.container.original_only && dir!=1 {continue;}
            if r.proto!=0 && r.proto!=proto || r.direction!=0 && r.direction!=dir {continue;}
            if !r.sequences.is_empty() && !r.sequences.contains(&seq) {continue;}
            if !r.ports.is_empty() && !r.ports.iter().any(|&(a,b)|port>=a && port<=b) {continue;}
            if !r.lengths.is_empty() && !r.lengths.iter().any(|&(a,b)|payload.len()>=a && payload.len()<=b) {continue;}
            if let Some(xs)=&r.destinations {if !dst.map(|ip|xs.contains(&u32::from(ip))).unwrap_or(false){continue;}}
            if let Some(ns)=&r.subnets {if !dst.map(|ip|ns.iter().any(|&(net,mask)|u32::from(ip)&mask==net)).unwrap_or(false){continue;}}
            if let Some((count,slot))=r.container.slot{if port as usize%count!=slot{continue;}}
            let raw_buffer=match &r.target{Target::Sni(_)=>sni.as_deref(),_=>Some(payload)};
            if !matches!(&r.target,Target::Http(_)|Target::Metadata) && raw_buffer.and_then(|b|content_slice(b,r.offset)).is_none(){continue;}
            if let Some(prefix)=&r.container.payload_prefix{if !raw_buffer.map(|b|b.starts_with(prefix)).unwrap_or(false){continue;}}
            if let Some((i,prefix))=&r.container.header_prefix{if !headers.as_ref().and_then(|h|h.get(i)).map(|h|h.starts_with(prefix)).unwrap_or(false){continue;}}
            if let Some((i,suffix))=&r.container.header_suffix{if !headers.as_ref().and_then(|h|h.get(i)).map(|h|h.ends_with(suffix)).unwrap_or(false){continue;}}
            if let Some((i,exact))=&r.container.header_exact{if !headers.as_ref().and_then(|h|h.get(i)).map(|h|h==exact).unwrap_or(false){continue;}}
            let (matched,kind)=match &r.target {
                Target::Payload(p)=>(content_slice(payload,r.offset).map(|s|p.matches(s)).unwrap_or(false),"payload"),
                Target::TlsData(p)=>(content_slice(payload,r.offset).map(|s|p.matches(s)).unwrap_or(false),"tls_data"),
                Target::Sni(p)=>(sni.as_ref().and_then(|s|content_slice(s,r.offset)).map(|s|p.matches(s)).unwrap_or(false),"tls_sni"),
                Target::Http(hs)=>(headers.as_ref().map(|hdr|hs.iter().all(|(i,p)|hdr.get(i).map(|s|!s.is_empty() && p.matches(s)).unwrap_or(false))).unwrap_or(false),"http_header"),
                Target::Metadata=>(true,"metadata"),
            };
            if matched {
                if let Some(ref mut indices)=matched_indices{indices.push(index);}
                out.push(Hit{appid:r.appid,rule_id:r.id,priority:r.priority,kind:kind.into()});
            }
        }
        // Preserve every match for audit; decide() applies the explicit portable
        // priority policy separately instead of hiding lower-priority evidence.
        out.sort_by_key(|h|(h.appid,h.rule_id));Ok(out)
    }
}

fn content_slice(b:&[u8],offset:i32)->Option<&[u8]> {
    let start=if offset<0 {let start=b.len().checked_sub(offset.unsigned_abs() as usize)?;if start==0{return None;}start}
        else {offset as usize};
    if start>=b.len(){None}else{b.get(start..)}
}
fn u16be(b:&[u8],p:usize)->Option<usize>{Some(u16::from_be_bytes([*b.get(p)?,*b.get(p+1)?]) as usize)}
pub fn tls_sni(b:&[u8])->Option<Vec<u8>>{
    if b.len()<9 || b[0]!=22 || b[1]!=3 || b[5]!=1 {return None;}
    let record_end=5+u16be(b,3)?;
    if record_end>b.len() {return None;}
    let hlen=((b[6] as usize)<<16)|((b[7] as usize)<<8)|b[8] as usize;
    let end=9usize.checked_add(hlen)?;
    if end>record_end || end<44 {return None;}
    let b=&b[..end];let mut p=43;
    p+=1+*b.get(p)? as usize;
    let n=u16be(b,p)?;p+=2+n;
    p+=1+*b.get(p)? as usize;
    let ext_end=p+2+u16be(b,p)?;p+=2;
    if ext_end!=end{return None;}
    while p+4<=ext_end {
        let kind=u16be(b,p)?;let n=u16be(b,p+2)?;p+=4;
        let next=p.checked_add(n)?;if next>ext_end{return None;}
        if kind==0 {
            let list_end=p+2+u16be(b,p)?;p+=2;
            if list_end!=next{return None;}
            while p+3<=list_end {
                let ty=b[p];let len=u16be(b,p+1)?;p+=3;
                if p+len>list_end{return None;}
                if ty==0 && len>0 && len<=127 {
                    let name=&b[p..p+len];
                    if name.iter().all(|c|c.is_ascii_alphanumeric() || b".-_".contains(c)){return Some(name.to_vec());}
                    return None;
                }
                p+=len;
            }
            return None;
        }
        p=next;
    }
    None
}
// Wire lookup table at .rodata+0x5840, rather than the display-name table:
// the latter misspells X-Requested-With and Set-Cookie.
const HTTP_WIRE_HEADERS:&[(&[u8],u64)]=&[
    (b"Host",1),(b"User-Agent",2),(b"Referer",3),(b"Pragma",5),(b"Accept",6),
    (b"Cookie",7),(b"Keep-Alive",8),(b"Cache-Control",9),(b"Content-Encoding",10),
    (b"Content-Language",11),(b"Content-Type",12),(b"Range",13),(b"Content-Length",14),
    (b"Connection",15),(b"Date",16),(b"Transfer-Encoding",17),(b"Upgrade",18),(b"Via",19),
    (b"Accept-Charset",20),(b"Accept-Encoding",21),(b"Accept-Language",22),(b"Authorization",23),
    (b"From",24),(b"If-Modified-Since",25),(b"If-Match",26),(b"If-None-Match",27),(b"If-Range",28),
    (b"If-Unmodified-Since",29),(b"Max-Forwards",30),(b"Proxy-Authorization",31),(b"Age",32),
    (b"Location",33),(b"Proxy-Authenticate",34),(b"Public",35),(b"Retry-After",36),(b"Server",37),
    (b"Vary",38),(b"Warning",39),(b"WWW-Authenticate",40),(b"Allow",41),(b"Content-Base",42),
    (b"Content-Location",43),(b"Content-MD5",44),(b"Content-Range",45),(b"Etag",46),
    (b"Expires",47),(b"Last-Modified",48),(b"Version",49),(b"Status",50),
    (b"X-Requested-With",56),(b"Set-Cookie",57),
];
pub fn http_headers(b:&[u8])->Option<BTreeMap<u64,Vec<u8>>>{
    let end=b.windows(4).position(|x|x==b"\r\n\r\n")?;
    let mut lines=b[..end].split(|c|*c==b'\n');
    let first=lines.next()?.strip_suffix(b"\r").unwrap_or(&b[..end]);
    let mut parts=first.split(|c|*c==b' ');let method=parts.next()?;
    let response=method==b"HTTP/1.0" || method==b"HTTP/1.1";
    let mut out=BTreeMap::new();let mut sequence=Vec::new();
    if response {
        let status=parts.next()?;
        if status.len()!=3 || !status.iter().all(u8::is_ascii_digit){return None;}
    }else{
        if ![b"GET".as_slice(),b"POST",b"HEAD",b"PUT",b"DELETE",b"OPTIONS",b"CONNECT",b"PATCH",b"TRACE"].contains(&method){return None;}
        let url=parts.next()?;let version=parts.next()?;
        if url.is_empty() || ![b"HTTP/1.0".as_slice(),b"HTTP/1.1"].contains(&version) || parts.next().is_some(){return None;}
        out.insert(0,url.to_vec());sequence.push(0);
        // get_url_ext: final dot after the last slash, before '?', maximum five
        // bytes; the native routine applies bitwise OR 0x20 to each byte.
        let path=url.split(|x|*x==b'?').next()?;
        let base=path.rsplit(|x|*x==b'/').next()?;
        if let Some(dot)=base.iter().rposition(|x|*x==b'.') {
            let ext=&base[dot+1..];if !ext.is_empty(){out.insert(52,ext.iter().take(5).map(|x|x|0x20).collect());}
        }
    }
    let mut private=0;
    for line in lines {
        let line=line.strip_suffix(b"\r").unwrap_or(line);
        if line.first().map(|x|x.is_ascii_whitespace()).unwrap_or(false){return None;}
        let pos=line.iter().position(|c|*c==b':')?;let key=&line[..pos];
        if key.is_empty() || !key.iter().all(|x|x.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(x)){return None;}
        let mut value=&line[pos+1..];while value.first().map(|x|matches!(x,b' '|b'\t')).unwrap_or(false){value=&value[1..];}
        let idx=if let Some((_,i))=HTTP_WIRE_HEADERS.iter().find(|(name,_)|key.eq_ignore_ascii_case(name)){*i}
            else {let i=match private {0=>51,1=>54,2=>55,_=>continue};private+=1;i};
        // A split/duplicate field has vendor callback overwrite semantics. Reject
        // it here instead of broadening to concatenated or arbitrary values.
        if out.insert(idx,value.to_vec()).is_some(){return None;}
        if sequence.len()<16{sequence.push(idx as u8);}
    }
    let body=&b[end+4..];
    let body_len=if out.contains_key(&17){None}
        else if let Some(length)=out.get(&14){
            std::str::from_utf8(length).ok().and_then(|s|s.parse::<usize>().ok()).filter(|n|*n<=body.len())
        }else if response{Some(body.len())}else{Some(0)};
    if let Some(n)=body_len.filter(|n|*n>0) {
        if sequence.len()<16{sequence.push(53);}
        // Native gzip/deflate decoding is not yet reproduced. Header predicates
        // remain usable; the Body field is absent for encoded/chunked messages.
        if !out.contains_key(&10){out.insert(53,body[..n].to_vec());}
    }
    if !sequence.is_empty(){out.insert(4,sequence);}
    Some(out)
}

#[cfg(test)]
mod semantics_tests {
    use super::*;
    fn app()->Value {json!({"_type":"IK_APP","proto":6,"dir":1,"pkt_seq":1,"appid":1540005,"data":{"hex":"4142"},"rule_id":1})}
    fn http(method:Option<u64>)->Value {
        let mut h=json!({"_type":"HTTPHEADER","index":1,"data":"abc"});
        if let Some(m)=method{h["match_method"]=json!(m);}
        json!({"_type":"IK_HTTP_APP","appid":1540005,"dir":1,"pkt_seq":1,"rule_id":2,"http_info":{"_type":"HTTPINFO","header":[h]}})
    }
    fn tree()->Value {json!({"_type":"APP","extend_ik_data":{"_type":"EXTEND_IK_DATA","slot":vec![json!({"_type":"IK_APP_SLOT"});4096],"prefix_match_apps":[{"offset":4,"hslot_cnt":512,"apps":{}}],"postfix_match_happs":[{"index":1,"offset":7,"hslot_cnt":512,"happs":{}}]}})}
    fn one(v:&Value,path:&str)->Matcher {Matcher{rules:vec![compile(v,path,Some(&tree())).unwrap()],audit:json!({})}}
    const APP:&str="APP.extend_ik_data.slot[0].ik_app[0]";
    const HTTP:&str="APP.extend_ik_data.http_app[0]";
    #[test]
    fn defaults_offsets_and_sequence_intersection() {
        let mut a=app();let m=one(&a,APP);
        assert_eq!(m.rules[0].priority,5);
        assert_eq!(m.match_packet(6,1,1,80,b"AB-tail").unwrap().len(),1);
        assert!(m.match_packet(6,1,1,80,b"xAB").unwrap().is_empty());
        a["offset"]=json!(1);assert_eq!(one(&a,APP).match_packet(6,1,1,80,b"xAB").unwrap().len(),1);
        a["offset"]=json!(-1);assert!(compile(&a,APP,Some(&tree())).is_err());
        a.as_object_mut().unwrap().remove("offset");
        a["multi_seq"]=json!({"_type":"MultiPktSeq","pkt_seq":[1,2]});
        let m=one(&a,APP);
        assert_eq!(m.match_packet(6,1,1,80,b"AB").unwrap().len(),1);
        assert!(m.match_packet(6,1,2,80,b"AB").unwrap().is_empty());
        a["multi_seq"]["pkt_seq"]=json!([2]);assert!(compile(&a,APP,Some(&tree())).is_err());
    }
    #[test]
    fn http_absent_regex_explicit_exact_and_prefix_are_distinct() {
        let request=b"GET / HTTP/1.1\r\nHost: abc-tail\r\n\r\n";
        let absent=one(&http(None),HTTP);assert_eq!(absent.rules[0].priority,105);
        assert_eq!(absent.match_packet(6,1,1,80,request).unwrap().len(),1);
        assert!(one(&http(Some(0)),HTTP).match_packet(6,1,1,80,request).unwrap().is_empty());
        assert_eq!(one(&http(Some(4)),HTTP).match_packet(6,1,1,80,request).unwrap().len(),1);
        assert!(compile(&http(Some(1)),HTTP,Some(&tree())).is_err());
        assert!(one(&http(Some(5)),HTTP).match_packet(6,1,1,80,b"GET /abc HTTP/1.1\r\nHost: nope\r\n\r\nabc").unwrap().is_empty());
    }
    #[test]
    fn binary_regex_cannot_gain_host_engine_extensions() {
        let p=Pattern::compile(br"^a.\x00[0-9]+$".to_vec(),1).unwrap();
        assert!(p.matches(b"a\n\0".iter().chain(b"123").copied().collect::<Vec<_>>().as_slice()));
        assert!(!p.matches(b"aZ\0"));
        assert!(!p.matches(b"aZ\x001\n"));
        for bad in [br"(?i)abc".as_slice(),br"[a&&b]"] {
            if bad==br"[a&&b]" {
                let literal=Pattern::compile(bad.to_vec(),1).unwrap();assert!(literal.matches(b"&"));
            }else{assert!(Pattern::compile(bad.to_vec(),1).is_err(),"{bad:?}");}
        }
        assert!(Pattern::compile(b"\xff".to_vec(),1).unwrap().matches(b"\xff"));
        assert!(Pattern::compile(br"a{2}\t".to_vec(),1).unwrap().matches(b"a{2}t"));
        assert!(!Pattern::compile(br"\d".to_vec(),1).unwrap().matches(b"3"));
        let cls=Pattern::compile(br"^[^\.]$".to_vec(),1).unwrap();
        assert!(!cls.matches(b"\\"));assert!(!cls.matches(b"."));assert!(cls.matches(b"x"));
    }
    #[test]
    fn slot_scope_survives_flattening() {
        let m=one(&app(),"APP.extend_ik_data.slot[443].ik_app[0]");
        assert_eq!(m.match_packet(6,1,1,443,b"AB").unwrap().len(),1);
        assert_eq!(m.match_packet(6,1,1,4539,b"AB").unwrap().len(),1);
        assert!(m.match_packet(6,1,1,80,b"AB").unwrap().is_empty());
        assert!(compile(&app(),"APP.extend_ik_data.unknown.ik_app[0]",Some(&tree())).is_err());
        assert!(compile(&app(),APP,None).is_err());
    }
    #[test]
    fn raw_container_keys_are_additional_to_regex() {
        let mut a=app();a["data"]=json!({"hex":"5e2e414243"});a["match_method"]=json!(1);
        let m=one(&a,"APP.extend_ik_data.prefix_match_apps[0].apps.ik_app[0]");
        assert_eq!(m.match_packet(6,1,1,80,b".ABC").unwrap().len(),1);
        assert!(m.match_packet(6,1,1,80,b"xABC").unwrap().is_empty());
        let mut h=http(None);h["http_info"]["header"][0]["data"]=json!("^update.leigod.com$");
        let m=one(&h,"APP.extend_ik_data.postfix_match_happs[0].happs.http_app[0]");
        assert_eq!(m.match_packet(6,1,1,80,b"GET / HTTP/1.1\r\nHost: update.leigod.com\r\n\r\n").unwrap().len(),1);
        assert!(m.match_packet(6,1,1,80,b"GET / HTTP/1.1\r\nHost: update.leigodXcom\r\n\r\n").unwrap().is_empty());
    }
    #[test]
    fn unsupported_constraints_never_drop_silently() {
        for field in ["expect_conn","dup_bytes","dup_block","multi_data","capture_ip","new_predicate"] {
            let mut a=app();a[field]=json!({});assert!(compile(&a,APP,Some(&tree())).is_err(),"{field}");
        }
        let mut a=app();a["pkt_seq"]=json!(-1);assert!(compile(&a,APP,Some(&tree())).is_err());
        a=app();a["match_flag"]=json!(1);assert!(compile(&a,APP,Some(&tree())).is_err());
        let mut h=http(None);h["proto"]=json!(17);assert!(compile(&h,HTTP,Some(&tree())).is_err());
    }
}
