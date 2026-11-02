use landscape_common::dns::config::DnsUpstreamConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    DnsUpstreamConfigActiveModel, DnsUpstreamConfigEntity, DnsUpstreamConfigModel,
};
use crate::DBId;

#[derive(Clone)]
pub struct DnsUpstreamRepository {
    db: DatabaseConnection,
}

impl DnsUpstreamRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    DnsUpstreamRepository,
    DnsUpstreamConfigModel,
    DnsUpstreamConfigEntity,
    DnsUpstreamConfigActiveModel,
    DnsUpstreamConfig,
    DBId
);

#[async_trait::async_trait]
impl landscape_common::database::validator::StoreValidator<DnsUpstreamConfig>
    for DnsUpstreamRepository
{
    async fn check_zone(
        &self,
        _: &DnsUpstreamConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        Ok(())
    }
    async fn validate_cross(
        &self,
        config: &mut DnsUpstreamConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        use landscape_common::{database::store::ConfigStore, service::ServiceConfigError};
        if let Some(id) = config.bind_config.follow_flow.filter(|id| *id != 0) {
            let flows = crate::flow_rule::repository::FlowConfigRepository::new(self.db.clone())
                .list()
                .await
                .map_err(ServiceConfigError::internal)?;
            if !flows
                .iter()
                .any(|flow| flow.flow_id == id && flow.enable && flow.failover.ordered_targets())
            {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: "DNS WAN binding requires an enabled primary/backup flow".into(),
                });
            }
        }
        if !config.bind_config.wan_servers.is_empty() {
            let links = crate::wan_link::repository::WanLinkRepository::new(self.db.clone())
                .net_iface_map()
                .await
                .map_err(ServiceConfigError::internal)?;
            for servers in &config.bind_config.wan_servers {
                if !links.contains_key(&servers.link_id) {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: format!("DNS WAN {} does not exist", servers.link_id),
                    });
                }
            }
        }
        config.bind_config.resolved_wan = None;
        Ok(())
    }
}
