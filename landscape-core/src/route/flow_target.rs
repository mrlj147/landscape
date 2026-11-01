//! Flow-config → WAN target slot join.
//!
//! The flow side owns the configs and pushes them in via
//! [`IpRouteService::sync_flow_wan_targets`] after config changes and on
//! every [`WanRouteEvent`](super::WanRouteEvent); the join itself lives here
//! next to the WAN state it reads.

use std::collections::HashMap;

use landscape_common::{
    config::FlowId,
    flow::{FlowTarget, config::FlowConfig},
    sys_service::route_service::{RouteOwner, WanRouteTarget, dataplane::RouteTableDataplane},
    wan_link::WanLinkHealthState,
};

use super::{IpRouteService, LinkHealths, WanRoutesByOwner};
use uuid::Uuid;

fn find_route_target<'a>(
    wan_infos: &'a WanRoutesByOwner,
    target: &FlowTarget,
) -> Option<&'a WanRouteTarget> {
    match target {
        FlowTarget::Interface { link_id, .. } => wan_infos.get(&RouteOwner::Link(*link_id)),
        FlowTarget::Netns { container_name } => {
            wan_infos.get(&RouteOwner::Netns(container_name.clone()))
        }
    }
}

pub(super) fn collect_target_refresh_result(
    flow_configs: &[FlowConfig],
    wan_infos: &WanRoutesByOwner,
) -> HashMap<FlowId, Vec<(WanRouteTarget, u32)>> {
    let mut result = HashMap::new();

    for flow_config in flow_configs {
        let targets = if flow_config.enable {
            flow_config
                .flow_targets
                .iter()
                .filter_map(|target| {
                    find_route_target(wan_infos, &target.target)
                        .cloned()
                        .map(|route| (route, target.weight))
                })
                .collect()
        } else {
            Vec::new()
        };

        result.insert(flow_config.flow_id, targets);
    }

    result
}

/// Serializes reconciliation and remembers the active exit when automatic
/// failback is disabled. IPv4 and IPv6 have independent route availability.
#[derive(Default)]
pub(super) struct FailoverSelections {
    active: HashMap<(FlowId, bool), ActiveFailover>,
}

struct ActiveFailover {
    order: Vec<Uuid>,
    selected: Option<Uuid>,
}

impl FailoverSelections {
    fn resolve(
        &mut self,
        configs: &[FlowConfig],
        routes: &WanRoutesByOwner,
        health: &LinkHealths,
        ipv6: bool,
    ) -> HashMap<FlowId, Vec<(WanRouteTarget, u32)>> {
        let mut result = collect_target_refresh_result(configs, routes);
        for config in configs {
            let key = (config.flow_id, ipv6);
            if !config.enable || !config.failover.enable {
                self.active.remove(&key);
                continue;
            }
            let order: Vec<Uuid> = config
                .flow_targets
                .iter()
                .filter_map(|target| match target.target {
                    FlowTarget::Interface { link_id, .. } => Some(link_id),
                    FlowTarget::Netns { .. } => None,
                })
                .collect();
            let available = |id: &Uuid| {
                routes.contains_key(&RouteOwner::Link(*id))
                    && health.get(id).is_some_and(|info| info.state == WanLinkHealthState::Healthy)
            };
            let previous = self
                .active
                .get(&key)
                .and_then(|old| (old.order == order).then_some(old.selected).flatten());
            let selected =
                if !config.failover.auto_failback && previous.as_ref().is_some_and(available) {
                    previous
                } else {
                    order.iter().copied().find(available)
                };
            if previous != selected {
                tracing::info!(
                    flow_id = config.flow_id,
                    ipv6,
                    ?previous,
                    ?selected,
                    "WAN failover exit changed"
                );
            }
            let targets = selected
                .and_then(|id| routes.get(&RouteOwner::Link(id)))
                .map(|route| vec![(route.clone(), 1)])
                .unwrap_or_default();
            result.insert(config.flow_id, targets);
            self.active.insert(key, ActiveFailover { order, selected });
        }
        result
    }

    pub(super) fn remove(&mut self, flow_id: FlowId) {
        self.active.remove(&(flow_id, false));
        self.active.remove(&(flow_id, true));
    }
}

fn warn_fully_unresolved_flows(
    flow_configs: &[FlowConfig],
    ipv4_result: &HashMap<FlowId, Vec<(WanRouteTarget, u32)>>,
    ipv6_result: &HashMap<FlowId, Vec<(WanRouteTarget, u32)>>,
) {
    for flow_config in flow_configs {
        if !flow_config.enable || flow_config.flow_targets.is_empty() {
            continue;
        }
        let unresolved = |result: &HashMap<FlowId, Vec<_>>| {
            result.get(&flow_config.flow_id).is_none_or(|t| t.is_empty())
        };
        if unresolved(ipv4_result) && unresolved(ipv6_result) {
            tracing::warn!(
                flow_id = flow_config.flow_id,
                "flow targets resolve to no WAN route in either address family; the flow's traffic is dropped until its link returns"
            );
        }
    }
}

fn apply_ipv4_target_refresh_result(
    dataplane: &dyn RouteTableDataplane,
    result: HashMap<FlowId, Vec<(WanRouteTarget, u32)>>,
) {
    tracing::info!("ipv4 flow target refresh result: {result:#?}");

    for (flow_id, configs) in result {
        if configs.is_empty() {
            dataplane.del_wan_slots_v4(flow_id);
        } else {
            dataplane.replace_wan_slots_v4(flow_id, &configs);
        }
    }
}

fn apply_ipv6_target_refresh_result(
    dataplane: &dyn RouteTableDataplane,
    result: HashMap<FlowId, Vec<(WanRouteTarget, u32)>>,
) {
    tracing::info!("ipv6 flow target refresh result: {result:#?}");

    for (flow_id, configs) in result {
        if configs.is_empty() {
            dataplane.del_wan_slots_v6(flow_id);
        } else {
            dataplane.replace_wan_slots_v6(flow_id, &configs);
        }
    }
}

impl IpRouteService {
    /// Recompute the per-flow WAN target slots for `flow_configs` against the
    /// current WAN route state and sync them into the eBPF maps.
    pub async fn sync_flow_wan_targets(&self, flow_configs: &[FlowConfig]) {
        let mut selections = self.failover_selections.lock().await;
        let health = self.clone_link_healths().await;
        let ipv4_wan_infos = self.clone_ipv4_wan_infos().await;
        let ipv4_result = selections.resolve(flow_configs, &ipv4_wan_infos, &health, false);

        let ipv6_wan_infos = self.clone_ipv6_wan_infos().await;
        let ipv6_result = selections.resolve(flow_configs, &ipv6_wan_infos, &health, true);

        warn_fully_unresolved_flows(flow_configs, &ipv4_result, &ipv6_result);

        apply_ipv4_target_refresh_result(&*self.dataplane, ipv4_result);
        apply_ipv6_target_refresh_result(&*self.dataplane, ipv6_result);

        self.dataplane.invalidate_lan_cache();
    }

    /// Drop all WAN target slots of `flow_id` (e.g. after the flow config is
    /// deleted).
    pub async fn clear_flow_wan_targets(&self, flow_id: FlowId) {
        let mut selections = self.failover_selections.lock().await;
        selections.remove(flow_id);
        self.dataplane.del_wan_slots_v4(flow_id);
        self.dataplane.del_wan_slots_v6(flow_id);
        self.dataplane.invalidate_lan_cache();
    }
}

#[cfg(test)]
mod failover_tests {
    use super::*;
    use landscape_common::flow::{FlowFailoverConfig, WeightedFlowTarget};
    use landscape_common::sys_service::route_service::RouteTargetInfo;
    use landscape_common::wan_link::HealthEvaluator;
    use std::net::Ipv4Addr;

    fn setup() -> (FlowConfig, WanRoutesByOwner, LinkHealths, Uuid, Uuid) {
        let primary = Uuid::from_u128(1);
        let backup = Uuid::from_u128(2);
        let mut routes = WanRoutesByOwner::new();
        let mut health = LinkHealths::new();
        for (id, name, index) in [(primary, "wan1", 1), (backup, "wan2", 2)] {
            routes.insert(
                RouteOwner::Link(id),
                WanRouteTarget::link(
                    index as u16,
                    RouteTargetInfo::new_gateway_v4(
                        index,
                        name,
                        None,
                        Ipv4Addr::new(192, 0, 2, index as u8),
                        Ipv4Addr::new(192, 0, 2, 254),
                        false,
                    ),
                ),
            );
            let mut info = HealthEvaluator::new(id, 3, 3, 1).info().clone();
            info.state = WanLinkHealthState::Healthy;
            health.insert(id, info);
        }
        let config = FlowConfig {
            id: Uuid::nil(),
            enable: true,
            flow_id: 9,
            flow_match_rules: vec![],
            flow_targets: [primary, backup]
                .into_iter()
                .map(|link_id| {
                    WeightedFlowTarget::new(
                        FlowTarget::Interface { link_id, name: String::new() },
                        7,
                    )
                })
                .collect(),
            failover: FlowFailoverConfig { enable: true, auto_failback: true },
            name: String::new(),
            remark: String::new(),
            update_at: 0.0,
        };
        (config, routes, health, primary, backup)
    }

    fn selected(
        state: &mut FailoverSelections,
        config: &FlowConfig,
        routes: &WanRoutesByOwner,
        health: &LinkHealths,
    ) -> Vec<String> {
        state.resolve(std::slice::from_ref(config), routes, health, false)[&9]
            .iter()
            .map(|(target, _)| target.info.iface_name.clone())
            .collect()
    }

    #[test]
    fn fails_over_on_probe_failure_and_returns_after_recovery() {
        let (config, routes, mut health, primary, _) = setup();
        let mut state = FailoverSelections::default();
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan1"]);
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Unhealthy;
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan2"]);
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Healthy;
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan1"]);
    }

    #[test]
    fn missing_route_overrides_stale_healthy_verdict() {
        let (config, mut routes, health, primary, _) = setup();
        routes.remove(&RouteOwner::Link(primary));
        assert_eq!(
            selected(&mut FailoverSelections::default(), &config, &routes, &health),
            ["wan2"]
        );
    }

    #[test]
    fn unknown_or_both_failed_never_falls_back_to_an_unrelated_wan() {
        let (config, routes, mut health, primary, backup) = setup();
        let mut state = FailoverSelections::default();
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Unknown;
        health.get_mut(&backup).unwrap().state = WanLinkHealthState::Unhealthy;
        assert!(selected(&mut state, &config, &routes, &health).is_empty());
        health.clear();
        assert!(selected(&mut state, &config, &routes, &health).is_empty());
    }

    #[test]
    fn sticky_backup_survives_recovery_but_order_changes_apply() {
        let (mut config, routes, mut health, primary, backup) = setup();
        let mut state = FailoverSelections::default();
        config.failover.auto_failback = false;
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Unhealthy;
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan2"]);
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Healthy;
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan2"]);
        health.get_mut(&backup).unwrap().state = WanLinkHealthState::Unhealthy;
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan1"]);
        health.get_mut(&backup).unwrap().state = WanLinkHealthState::Healthy;
        config.flow_targets.reverse();
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan2"]);
    }

    #[test]
    fn disabling_failover_preserves_weights_and_disabled_flow_has_no_slots() {
        let (mut config, routes, _, _, _) = setup();
        let mut state = FailoverSelections::default();
        config.failover.enable = false;
        let result = state.resolve(&[config.clone()], &routes, &LinkHealths::new(), false);
        assert_eq!(result[&9].len(), 2);
        assert!(result[&9].iter().all(|(_, weight)| *weight == 7));
        config.enable = false;
        assert!(selected(&mut state, &config, &routes, &LinkHealths::new()).is_empty());
    }

    #[test]
    fn address_families_select_only_routes_in_their_own_table() {
        let (config, routes, health, _, _) = setup();
        let mut state = FailoverSelections::default();
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan1"]);
        let empty = state.resolve(&[config], &WanRoutesByOwner::new(), &health, true);
        assert!(empty[&9].is_empty());
    }
}
