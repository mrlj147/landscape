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

/// Selection clocks are monotonic; wall time is used only for the status API.
#[derive(Default)]
pub(super) struct FailoverSelections {
    active: HashMap<(FlowId, bool), ActiveFailover>,
    published: HashMap<(FlowId, bool), Vec<(WanRouteTarget, u32)>>,
}

struct ActiveFailover {
    order: Vec<Uuid>,
    selected: Option<Uuid>,
    generation: u64,
    selection_changed: bool,
    changed: std::time::Instant,
    unknown_since: HashMap<Uuid, std::time::Instant>,
    healthy_since: HashMap<Uuid, std::time::Instant>,
    status: landscape_common::flow::failover::FlowWanStatus,
}

impl FailoverSelections {
    fn resolve(
        &mut self,
        configs: &[FlowConfig],
        routes: &WanRoutesByOwner,
        health: &LinkHealths,
        ipv6: bool,
    ) -> HashMap<FlowId, Vec<(WanRouteTarget, u32)>> {
        self.resolve_at(configs, routes, health, ipv6, std::time::Instant::now())
    }

    fn resolve_at(
        &mut self,
        configs: &[FlowConfig],
        routes: &WanRoutesByOwner,
        health: &LinkHealths,
        ipv6: bool,
        now: std::time::Instant,
    ) -> HashMap<FlowId, Vec<(WanRouteTarget, u32)>> {
        use landscape_common::flow::failover::{
            FlowWanCandidateStatus, FlowWanStatus, FlowWanSwitchEvent, WanSelectionReason as Reason,
        };
        use landscape_common::utils::time::now_ms;
        let mut result = collect_target_refresh_result(configs, routes);
        for config in configs {
            let key = (config.flow_id, ipv6);
            if !config.enable || !config.failover.ordered_targets() {
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
            let state = self.active.entry(key).or_insert_with(|| ActiveFailover {
                order: order.clone(),
                selected: None,
                generation: now_ms().saturating_mul(1000),
                selection_changed: false,
                changed: now,
                unknown_since: HashMap::new(),
                healthy_since: HashMap::new(),
                status: FlowWanStatus {
                    flow_id: config.flow_id,
                    ipv6,
                    automatic: config.failover.enable,
                    active_link_id: None,
                    active_iface_name: None,
                    selected_at_ms: now_ms(),
                    reason: Reason::NoAvailableWan,
                    retry_after_secs: None,
                    candidates: vec![],
                    history: vec![],
                },
            });
            let reordered = state.order != order;
            let previous = state.selected;
            let has_route = |id: &Uuid| routes.contains_key(&RouteOwner::Link(*id));
            let verdict =
                |id: &Uuid| health.get(id).map_or(WanLinkHealthState::Unknown, |info| info.state);
            let healthy = |id: &Uuid| has_route(id) && verdict(id) == WanLinkHealthState::Healthy;
            for id in &order {
                if has_route(id) && verdict(id) == WanLinkHealthState::Unknown {
                    state.unknown_since.entry(*id).or_insert(now);
                } else {
                    state.unknown_since.remove(id);
                }
                if healthy(id) {
                    state.healthy_since.entry(*id).or_insert(now);
                } else {
                    state.healthy_since.remove(id);
                }
            }
            state.unknown_since.retain(|id, _| order.contains(id));
            state.healthy_since.retain(|id, _| order.contains(id));
            let best = order.iter().copied().find(healthy);
            let mut retry_after_secs = None;
            let (selected, reason) = if !config.failover.enable {
                (order.first().copied().filter(has_route), Reason::ManualPrimary)
            } else if !reordered && previous.is_some_and(|id| healthy(&id)) {
                if !config.failover.auto_failback {
                    (previous, Reason::StickyBackup)
                } else if best != previous {
                    let candidate = best.expect("healthy current exit implies a healthy candidate");
                    let stable = now.duration_since(state.healthy_since[&candidate]).as_secs();
                    let held = now.duration_since(state.changed).as_secs();
                    let wait = u64::from(config.failover.failback_delay_secs)
                        .saturating_sub(stable)
                        .max(u64::from(config.failover.switch_hold_secs).saturating_sub(held));
                    if wait > 0 {
                        retry_after_secs = Some(wait);
                        (previous, Reason::WaitingFailback)
                    } else {
                        (best, Reason::Healthy)
                    }
                } else {
                    (previous, Reason::Healthy)
                }
            } else if best.is_some() {
                (best, Reason::Healthy)
            } else {
                // Only configured, routed Unknown links qualify; known failures never do.
                let unknown =
                    |id: &Uuid| has_route(id) && verdict(id) == WanLinkHealthState::Unknown;
                let candidate =
                    previous.filter(unknown).or_else(|| order.iter().copied().find(unknown));
                match candidate {
                    Some(id) => {
                        let elapsed = now.duration_since(state.unknown_since[&id]).as_secs();
                        let remaining =
                            u64::from(config.failover.unknown_grace_secs).saturating_sub(elapsed);
                        if remaining > 0 {
                            retry_after_secs = Some(remaining);
                            (Some(id), Reason::StartupGrace)
                        } else if config.failover.fail_open_on_unknown {
                            (Some(id), Reason::UnknownFailOpen)
                        } else {
                            (None, Reason::NoAvailableWan)
                        }
                    }
                    None => (None, Reason::NoAvailableWan),
                }
            };
            state.selection_changed = previous != selected;
            if reordered || (state.status.automatic && !config.failover.enable) {
                state.generation = state.generation.wrapping_add(1);
            }
            if previous != selected {
                let recovery = !reordered && previous.is_some_and(|id| healthy(&id));
                let policy = if recovery {
                    config.failover.recovery_connection_policy
                } else {
                    config.failover.failure_connection_policy
                };
                if policy == landscape_common::flow::FlowConnectionPolicy::ResetExisting {
                    state.generation = state.generation.wrapping_add(1);
                }
                let at_ms = now_ms();
                state.status.selected_at_ms = at_ms;
                state.changed = now;
                state.status.history.push(FlowWanSwitchEvent {
                    at_ms,
                    previous,
                    active: selected,
                    reason,
                    connection_policy: policy,
                });
                if state.status.history.len() > 32 {
                    state.status.history.remove(0);
                }
                tracing::info!(
                    flow_id = config.flow_id,
                    ipv6,
                    ?previous,
                    ?selected,
                    ?reason,
                    ?policy,
                    "WAN failover exit changed"
                );
            }
            state.selected = selected;
            state.order = order.clone();
            state.status.automatic = config.failover.enable;
            state.status.active_link_id = selected;
            state.status.active_iface_name = selected
                .and_then(|id| routes.get(&RouteOwner::Link(id)))
                .map(|r| r.info.iface_name.clone());
            state.status.reason = reason;
            state.status.retry_after_secs = retry_after_secs;
            state.status.candidates = order
                .into_iter()
                .map(|id| FlowWanCandidateStatus {
                    link_id: id,
                    iface_name: routes
                        .get(&RouteOwner::Link(id))
                        .map(|r| r.info.iface_name.clone()),
                    route_available: has_route(&id),
                    health: verdict(&id),
                })
                .collect();
            let targets = selected
                .and_then(|id| routes.get(&RouteOwner::Link(id)))
                .map(|route| vec![(route.clone(), 1)])
                .unwrap_or_default();
            result.insert(config.flow_id, targets);
        }
        result
    }

    pub(super) fn remove(&mut self, flow_id: FlowId) {
        self.active.remove(&(flow_id, false));
        self.active.remove(&(flow_id, true));
        self.published.remove(&(flow_id, false));
        self.published.remove(&(flow_id, true));
    }

    fn changed_targets(
        &mut self,
        result: HashMap<FlowId, Vec<(WanRouteTarget, u32)>>,
        ipv6: bool,
    ) -> HashMap<FlowId, Vec<(WanRouteTarget, u32)>> {
        result
            .into_iter()
            .filter(|(id, targets)| {
                let key = (*id, ipv6);
                if self.published.get(&key) == Some(targets) {
                    return false;
                }
                self.published.insert(key, targets.clone());
                true
            })
            .collect()
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
    pub async fn get_flow_wan_statuses(
        &self,
    ) -> Vec<landscape_common::flow::failover::FlowWanStatus> {
        let selections = self.failover_selections.lock().await;
        let mut statuses: Vec<_> = selections.active.values().map(|s| s.status.clone()).collect();
        statuses.sort_by_key(|s| (s.flow_id, s.ipv6));
        statuses
    }

    /// Recompute the per-flow WAN target slots for `flow_configs` against the
    /// current WAN route state and sync them into the eBPF maps.
    pub async fn sync_flow_wan_targets(&self, flow_configs: &[FlowConfig]) {
        let mut selections = self.failover_selections.lock().await;
        let health = self.clone_link_healths().await;
        let ipv4_wan_infos = self.clone_ipv4_wan_infos().await;
        let ipv4_result = selections.resolve(flow_configs, &ipv4_wan_infos, &health, false);

        let ipv6_wan_infos = self.clone_ipv6_wan_infos().await;
        let health_v6 = self.get_link_healths_for_family(true).await;
        let ipv6_result = selections.resolve(flow_configs, &ipv6_wan_infos, &health_v6, true);

        let ipv4_updates = selections.changed_targets(ipv4_result.clone(), false);
        let ipv6_updates = selections.changed_targets(ipv6_result.clone(), true);
        let changed = !ipv4_updates.is_empty() || !ipv6_updates.is_empty();
        // A reconnect/address change of the same WAN must not preserve stale
        // ifindex/gateway data, even though the link UUID did not change.
        for (ipv6, updates) in [(false, &ipv4_updates), (true, &ipv6_updates)] {
            for id in updates.keys() {
                if let Some(state) = selections.active.get_mut(&(*id, ipv6)) {
                    if !state.selection_changed {
                        state.generation = state.generation.wrapping_add(1);
                    }
                }
            }
        }
        if changed {
            warn_fully_unresolved_flows(flow_configs, &ipv4_result, &ipv6_result);
        }
        apply_ipv4_target_refresh_result(&*self.dataplane, ipv4_updates);
        apply_ipv6_target_refresh_result(&*self.dataplane, ipv6_updates);

        for config in flow_configs {
            for ipv6 in [false, true] {
                let generation =
                    selections.active.get(&(config.flow_id, ipv6)).map(|s| s.generation);
                self.dataplane.set_connection_generation(config.flow_id, ipv6, generation);
            }
        }
        if changed {
            self.dataplane.invalidate_lan_cache();
        }
    }

    /// Drop all WAN target slots of `flow_id` (e.g. after the flow config is
    /// deleted).
    pub async fn clear_flow_wan_targets(&self, flow_id: FlowId) {
        let mut selections = self.failover_selections.lock().await;
        selections.remove(flow_id);
        self.dataplane.set_connection_generation(flow_id, false, None);
        self.dataplane.set_connection_generation(flow_id, true, None);
        self.dataplane.del_wan_slots_v4(flow_id);
        self.dataplane.del_wan_slots_v6(flow_id);
        self.dataplane.invalidate_lan_cache();
    }
}

#[cfg(test)]
mod failover_tests {
    use super::*;
    use landscape_common::flow::{FlowFailoverConfig, FlowTargetMode, WeightedFlowTarget};
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
            failover: FlowFailoverConfig {
                mode: FlowTargetMode::PrimaryBackup,
                enable: true,
                auto_failback: true,
                unknown_grace_secs: 0,
                failback_delay_secs: 0,
                switch_hold_secs: 0,
                ..Default::default()
            },
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
    fn legacy_weighted_mode_and_disabled_flow_remain_unchanged() {
        let (mut config, routes, _, _, _) = setup();
        let mut state = FailoverSelections::default();
        config.failover.enable = false;
        config.failover.mode = FlowTargetMode::Weighted;
        let result = state.resolve(&[config.clone()], &routes, &LinkHealths::new(), false);
        assert_eq!(result[&9].len(), 2);
        assert!(result[&9].iter().all(|(_, weight)| *weight == 7));
        config.enable = false;
        assert!(selected(&mut state, &config, &routes, &LinkHealths::new()).is_empty());
    }

    #[test]
    fn automatic_switching_off_stays_on_primary_even_when_unhealthy() {
        let (mut config, mut routes, mut health, primary, _) = setup();
        let mut state = FailoverSelections::default();
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Unhealthy;
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan2"]);
        config.failover.enable = false;
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan1"]);
        routes.remove(&RouteOwner::Link(primary));
        assert!(
            selected(&mut state, &config, &routes, &health).is_empty(),
            "must not use backup while automatic switching is off"
        );
    }

    #[test]
    fn unknown_grace_expires_and_fail_open_never_revives_known_failure() {
        let (mut config, routes, mut health, primary, backup) = setup();
        config.failover.unknown_grace_secs = 30;
        health.clear();
        let mut state = FailoverSelections::default();
        let now = std::time::Instant::now();
        let resolve =
            |state: &mut FailoverSelections, cfg: &FlowConfig, health: &LinkHealths, secs| {
                state.resolve_at(
                    std::slice::from_ref(cfg),
                    &routes,
                    health,
                    false,
                    now + std::time::Duration::from_secs(secs),
                )[&9]
                    .clone()
            };
        assert_eq!(resolve(&mut state, &config, &health, 0)[0].0.info.iface_name, "wan1");
        assert_eq!(state.active[&(9, false)].status.retry_after_secs, Some(30));
        assert!(resolve(&mut state, &config, &health, 30).is_empty());
        config.failover.fail_open_on_unknown = true;
        assert_eq!(resolve(&mut state, &config, &health, 31)[0].0.info.iface_name, "wan1");
        let mut failed = HealthEvaluator::new(primary, 1, 1, 1).info().clone();
        failed.state = WanLinkHealthState::Unhealthy;
        health.insert(primary, failed.clone());
        assert_eq!(resolve(&mut state, &config, &health, 32)[0].0.info.iface_name, "wan2");
        failed.link_id = backup;
        health.insert(backup, failed);
        assert!(resolve(&mut state, &config, &health, 33).is_empty());
    }

    #[test]
    fn healthy_backup_wins_over_unknown_primary_even_during_grace() {
        let (mut config, routes, mut health, primary, _) = setup();
        config.failover.unknown_grace_secs = 60;
        config.failover.fail_open_on_unknown = true;
        health.remove(&primary);
        assert_eq!(
            selected(&mut FailoverSelections::default(), &config, &routes, &health),
            ["wan2"]
        );
    }

    #[test]
    fn failback_requires_continuous_health_but_emergency_failure_is_immediate() {
        let (mut config, routes, mut health, primary, backup) = setup();
        config.failover.failback_delay_secs = 30;
        let mut state = FailoverSelections::default();
        let now = std::time::Instant::now();
        let resolve = |state: &mut FailoverSelections, health: &LinkHealths, secs| {
            state.resolve_at(
                std::slice::from_ref(&config),
                &routes,
                health,
                false,
                now + std::time::Duration::from_secs(secs),
            )[&9][0]
                .0
                .info
                .iface_name
                .clone()
        };
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Unhealthy;
        assert_eq!(resolve(&mut state, &health, 0), "wan2");
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Healthy;
        assert_eq!(resolve(&mut state, &health, 1), "wan2");
        assert_eq!(resolve(&mut state, &health, 30), "wan2");
        assert_eq!(resolve(&mut state, &health, 31), "wan1");
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Unhealthy;
        assert_eq!(resolve(&mut state, &health, 32), "wan2");
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Healthy;
        assert_eq!(resolve(&mut state, &health, 33), "wan2");
        health.get_mut(&backup).unwrap().state = WanLinkHealthState::Unhealthy;
        assert_eq!(resolve(&mut state, &health, 34), "wan1");
        assert_eq!(state.active[&(9, false)].status.history.len(), 4);
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
