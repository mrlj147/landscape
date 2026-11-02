use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Source-address binding for connections to a DNS upstream. Optional: when
/// both addresses are `None` sockets bind to the OS-chosen source address.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsBindConfig {
    /// Follow this flow's selected WAN, including its source address and device.
    /// None keeps the existing source-address/OS routing behavior.
    #[serde(default)]
    pub follow_flow: Option<u32>,
    #[serde(skip)]
    #[cfg_attr(feature = "openapi", schema(ignore))]
    pub resolved_wan: Option<DnsWanBinding>,
    /// Source address for IPv4 connections to the upstream (optional)
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub bind_addr4: Option<Ipv4Addr>,
    /// Source address for IPv6 connections to the upstream (optional)
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub bind_addr6: Option<Ipv6Addr>,
}

/// Ephemeral binding resolved by the route service; never persisted or accepted
/// from an API request. Missing families fail closed when follow_flow is set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsWanBinding {
    pub ipv4: Option<(String, Ipv4Addr)>,
    pub ipv6: Option<(String, Ipv6Addr)>,
}

impl DnsBindConfig {
    pub fn socket_mark(&self, mark: u32) -> u32 {
        self.follow_flow.map_or(mark, |flow| (mark & !0xff) | (flow & 0xff))
    }

    pub fn source_addr(&self, ipv6: bool) -> Option<std::net::IpAddr> {
        if self.follow_flow.is_some() {
            let binding = self.resolved_wan.as_ref()?;
            if ipv6 {
                binding.ipv6.as_ref().map(|(_, ip)| (*ip).into())
            } else {
                binding.ipv4.as_ref().map(|(_, ip)| (*ip).into())
            }
        } else if ipv6 {
            self.bind_addr6.map(Into::into)
        } else {
            self.bind_addr4.map(Into::into)
        }
    }

    pub fn interface(&self, ipv6: bool) -> Option<&str> {
        let binding = self.resolved_wan.as_ref()?;
        if ipv6 {
            binding.ipv6.as_ref().map(|(name, _)| name.as_str())
        } else {
            binding.ipv4.as_ref().map(|(name, _)| name.as_str())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_binding_is_never_persisted_or_accepted_from_json() {
        let config = DnsBindConfig {
            follow_flow: Some(7),
            resolved_wan: Some(DnsWanBinding {
                ipv4: Some(("wan2".into(), "192.0.2.2".parse().unwrap())),
                ipv6: None,
            }),
            ..Default::default()
        };
        assert_eq!(config.socket_mark(0x8003), 0x8007);
        assert_eq!(config.interface(false), Some("wan2"));
        assert!(config.source_addr(true).is_none());
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("resolved_wan"));
        let mut json = serde_json::to_value(&config).unwrap();
        json["resolved_wan"] = serde_json::json!({"ipv4": ["evil", "192.0.2.3"]});
        let decoded: DnsBindConfig = serde_json::from_value(json).unwrap();
        assert!(decoded.resolved_wan.is_none());
        assert_eq!(decoded.follow_flow, Some(7));
    }
}
