use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::FlowConnectionPolicy;
use crate::wan_link::WanLinkHealthState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum WanSelectionReason {
    ManualPrimary,
    Healthy,
    StartupGrace,
    UnknownFailOpen,
    WaitingFailback,
    StickyBackup,
    NoAvailableWan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum WanSwitchCause {
    AvailableWan,
    ManualPrimary,
    PriorityChanged,
    LinkUnavailable,
    HealthFailure,
    HealthUnknown,
    UnknownGraceExpired,
    Recovery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowWanCandidateStatus {
    pub link_id: Uuid,
    pub iface_name: Option<String>,
    pub route_available: bool,
    pub health: WanLinkHealthState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowWanSwitchEvent {
    pub at_ms: u64,
    pub previous: Option<Uuid>,
    pub active: Option<Uuid>,
    pub reason: WanSelectionReason,
    pub connection_policy: FlowConnectionPolicy,
    pub cause: WanSwitchCause,
}

/// One independently selected address family. History is bounded and in-memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowWanStatus {
    pub flow_id: u32,
    pub ipv6: bool,
    pub automatic: bool,
    pub active_link_id: Option<Uuid>,
    pub active_iface_name: Option<String>,
    pub reason: WanSelectionReason,
    pub selected_at_ms: u64,
    pub retry_after_secs: Option<u64>,
    pub candidates: Vec<FlowWanCandidateStatus>,
    pub history: Vec<FlowWanSwitchEvent>,
}
