use dpi_bridge::{matcher::{Context,Matcher,decide},packet::Capture,replay::{self,Cidr,Replay}};
use dpi_bridge::matcher::expect::{ExpectTable,PacketState};
use serde::Deserialize;
use serde_json::json;
use std::{collections::{HashMap,HashSet},fs::File,io::{self,BufRead,BufReader,Read,Write},path::Path};

fn ids(s: &str) -> Result<HashSet<u32>,String> {s.split(',').map(|x|x.parse::<u32>().map_err(|_|"invalid numeric ID".into())).collect()}
#[derive(Deserialize)]
struct StatefulContext {context:Context,state:PacketState}
fn main(){if let Err(e)=execute(){eprintln!("dpi-bridge: {e}");std::process::exit(1);}}
fn execute()->Result<(),String>{
    let mut args=std::env::args().skip(1);let command=args.next().unwrap_or("help".into());
    if ["help","--help","-h"].contains(&command.as_str()) {println!("{}", "dpi-bridge 0.1.0 (full catalog, conservative matching)\n  audit --rules FILE [--appids IDS | --all] [--rule-ids IDS]\n  match --rules FILE [--appids IDS | --all] [--rule-ids IDS] < contexts.jsonl\n  stateful-match --rules FILE < stateful-contexts.jsonl\n  replay --rules FILE --pcap FILE_OR_- --client-cidr CIDR[,CIDR] [--appids IDS | --all] [--max-flows 4096]\n\nDefault: all applications. --appids restricts to a comma-separated ID list.\nUnsupported rules remain in audit.skipped; full extraction is not native-equivalent matching.\nmatch is explicitly stateless; EXPECT requires stateful-match or replay.\nstateful-match input: {context:{...},state:{flow:{client_ip,server_ip,client_port,server_port,protocol},direction,now_ms}}.\nCapture must begin before TCP connection setup. Output is JSONL; no network changes.\nPacket-level payload matching only; no TCP stream or IP fragment reassembly.");return Ok(());}
    if !["audit","match","stateful-match","replay"].contains(&command.as_str()){return Err("unknown command (use --help)".into());}
    let mut opts=HashMap::new();let mut all=false;
    while let Some(k)=args.next(){if k=="--all" {all=true;continue;}if !["--rules","--appids","--rule-ids","--pcap","--client-cidr","--max-flows"].contains(&k.as_str()){return Err(format!("unknown option {k}"));}let v=args.next().ok_or("option requires value")?;if opts.insert(k,v).is_some(){return Err("duplicate option".into());}}
    if all && opts.contains_key("--appids"){return Err("--all and --appids are mutually exclusive".into());}
    let selected=opts.get("--appids").map(|s|ids(s)).transpose()?.unwrap_or_default();
    let rule_ids=opts.get("--rule-ids").map(|x|ids(x)).transpose()?.unwrap_or_default();
    let rules=opts.get("--rules").ok_or("--rules is required")?;
    let matcher=Matcher::load_filtered(Path::new(rules),&selected,&rule_ids)?;
    if command=="audit" {println!("{}",serde_json::to_string_pretty(&matcher.audit).unwrap());return Ok(());}
    eprintln!("{}",json!({"event":"engine_audit","audit":matcher.audit}));
    let stdout=io::stdout();let mut output=io::BufWriter::new(stdout.lock());
    if command=="match" || command=="stateful-match" {
        let mut table=ExpectTable::default();
        let mut input=BufReader::new(io::stdin());let mut line=String::new();
        loop {line.clear();let n=(&mut input).take(131073).read_line(&mut line).map_err(|e|e.to_string())?;if n==0{break;}if n>=131073{return Err("context line exceeds bound".into());}if line.trim().is_empty(){continue;}
            if command=="stateful-match" {
                let record:StatefulContext=serde_json::from_str(&line).map_err(|e|e.to_string())?;
                let result=matcher.evaluate_stateful(&record.context,&mut table,&record.state)?;
                let mut value=serde_json::to_value(&result).map_err(|e|e.to_string())?;value["ambiguous"]=json!(result.decision.ambiguous || !result.state_issues.is_empty());
                writeln!(output,"{value}").map_err(|e|e.to_string())?;
            }else {
                let ctx:Context=serde_json::from_str(&line).map_err(|e|e.to_string())?;let hits=matcher.evaluate(&ctx)?;
                let decision=decide(&hits);
                writeln!(output,"{}",json!({"hits":hits,"ambiguous":decision.ambiguous,"decision":decision,"mode":"stateless","stateful_rules_not_evaluated":matcher.audit["stateful_rules"]})).map_err(|e|e.to_string())?;
            }
        }
    }else{
        let path=opts.get("--pcap").ok_or("--pcap is required")?;
        let reader:Box<dyn Read>=if path=="-"{Box::new(io::stdin())}else{Box::new(File::open(path).map_err(|e|e.to_string())?)};
        let mut capture=Capture::new(BufReader::new(reader))?;
        let cidrs=opts.get("--client-cidr").ok_or("--client-cidr is required")?.split(',').map(Cidr::parse).collect::<Result<Vec<_>,_>>()?;
        let limit=opts.get("--max-flows").map(|x|x.parse::<usize>().map_err(|_|"invalid max-flows")).transpose()?.unwrap_or(4096);
        let mut state=Replay::new(&matcher,cidrs,limit)?;
        replay::run(&mut capture,&mut state,|event|{writeln!(output,"{event}").map_err(|e|e.to_string())?;output.flush().map_err(|e|e.to_string())})?;
        eprintln!("{}",json!({"event":"replay_summary","stats":state.stats,"capture":{"packets_read":capture.packets_read,"malformed_packets":capture.malformed_packets,"skipped_packets":capture.skipped_packets}}));
    }
    output.flush().map_err(|e|e.to_string())?;Ok(())
}
