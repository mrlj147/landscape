//! Kernel gateway routes for SO_BINDTODEVICE sockets on non-default WANs.
//! The oif selector only matches locally originated, explicitly bound sockets;
//! unbound host traffic and forwarded client flows keep their normal policy.
use super::router::{apply, command, default_args, number, strings};
use landscape_common::sys_service::route_service::WanRouteTarget;
use serde_json::Value;

const KEEP_SPECIFIC: u64 = 10424;
const USE_BOUND_WAN: u64 = 10425;
const TABLE_BASE: u64 = 43000;
const MAX_CHAIN: u64 = 1023;

fn rule_args(family: &str, action: &str, iface: &str, table: u64, keep: bool) -> Vec<String> {
    let mut args = strings(&[family, "rule", action, "pref"]);
    args.push(if keep { KEEP_SPECIFIC } else { USE_BOUND_WAN }.to_string());
    args.extend(strings(&["iif", "lo", "oif", iface, "table"]));
    args.push(if keep { "main".into() } else { table.to_string() });
    args.extend(strings(&["protocol", "242"]));
    if keep {
        args.extend(strings(&["suppress_prefixlength", "0"]));
    }
    args
}
fn matches(rule: &Value, iface: &str, table: u64, keep: bool) -> bool {
    rule["oif"] == iface
        && number(&rule["priority"]) == Some(if keep { KEEP_SPECIFIC } else { USE_BOUND_WAN })
        && (keep || number(&rule["table"]) == Some(table))
}
async fn family(family: &str, targets: &[WanRouteTarget]) -> Result<(), String> {
    let wanted: Vec<_> = targets
        .iter()
        .filter(|t| {
            t.link_chain_id > 0
                && u64::from(t.link_chain_id) <= MAX_CHAIN
                && !t.info.is_docker
                && t.info.iface_ip.is_ipv6() == (family == "-6")
        })
        .collect();
    let list = command(&strings(&["-j", family, "rule", "show"])).await?;
    if !list.status.success() {
        return Err(String::from_utf8_lossy(&list.stderr).into());
    }
    let rules: Vec<Value> = serde_json::from_slice(&list.stdout).map_err(|e| e.to_string())?;
    let owned: Vec<_> = rules
        .iter()
        .filter(|r| matches!(number(&r["priority"]), Some(KEEP_SPECIFIC | USE_BOUND_WAN)))
        .collect();
    // Refuse foreign rules before changing any of this family's bindings.
    for rule in &owned {
        let keep = number(&rule["priority"]) == Some(KEEP_SPECIFIC);
        let valid_table = if keep {
            rule["table"] == "main" || number(&rule["table"]) == Some(254)
        } else {
            number(&rule["table"])
                .is_some_and(|t| (TABLE_BASE + 1..=TABLE_BASE + MAX_CHAIN).contains(&t))
        };
        if number(&rule["protocol"]) != Some(242)
            || rule["iif"] != "lo"
            || rule["oif"].as_str().is_none_or(str::is_empty)
            || !valid_table
            || !rule["fwmark"].is_null()
            || (keep && number(&rule["suppress_prefixlen"]) != Some(0))
        {
            return Err(format!(
                "bound WAN rule priority {} is owned by another policy",
                rule["priority"]
            ));
        }
    }
    for target in &wanted {
        let table = TABLE_BASE + u64::from(target.link_chain_id);
        let list = command(&strings(&["-j", family, "route", "show", "table", &table.to_string()]))
            .await?;
        if list.status.success() {
            let routes: Vec<Value> =
                serde_json::from_slice(&list.stdout).map_err(|e| e.to_string())?;
            if routes.iter().any(|r| number(&r["protocol"]) != Some(242)) {
                return Err(format!("bound WAN routing table {table} contains foreign routes"));
            }
        } else if !String::from_utf8_lossy(&list.stderr).contains("FIB table does not exist") {
            return Err(String::from_utf8_lossy(&list.stderr).into());
        }
        let mut args = default_args(family, Some(&target.info));
        args[4] = table.to_string();
        apply(args).await?;
        for keep in [true, false] {
            if !owned.iter().any(|r| matches(r, &target.info.iface_name, table, keep)) {
                apply(rule_args(family, "add", &target.info.iface_name, table, keep)).await?;
            }
        }
    }
    // Remove stale lookup rules before their main-table preservation rules.
    for keep in [false, true] {
        for rule in owned.iter().filter(|r| (number(&r["priority"]) == Some(KEEP_SPECIFIC)) == keep)
        {
            if wanted.iter().any(|t| {
                matches(rule, &t.info.iface_name, TABLE_BASE + u64::from(t.link_chain_id), keep)
            }) {
                continue;
            }
            let iface = rule["oif"].as_str().unwrap();
            let table = number(&rule["table"]).unwrap_or(254);
            apply(rule_args(family, "del", iface, table, keep)).await?;
            if !keep && !wanted.iter().any(|t| TABLE_BASE + u64::from(t.link_chain_id) == table) {
                // Deleting a device can already have removed its last route/table.
                let output = command(&strings(&[
                    family,
                    "route",
                    "flush",
                    "table",
                    &table.to_string(),
                    "proto",
                    "242",
                ]))
                .await?;
                if !output.status.success()
                    && !String::from_utf8_lossy(&output.stderr).contains("FIB table does not exist")
                {
                    return Err(String::from_utf8_lossy(&output.stderr).into());
                }
            }
        }
    }
    Ok(())
}
pub async fn sync_bound_wan_routes(targets: &[WanRouteTarget]) -> Result<(), String> {
    family("-4", targets).await?;
    family("-6", targets).await
}
