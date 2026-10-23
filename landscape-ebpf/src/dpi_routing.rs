//! Application admission maps, isolated from upstream route and NAT caches.
use libbpf_rs::{MapType, OpenMapMut, libbpf_sys};
use crate::bpf_error::LdEbpfResult;
use crate::maps::{MapCreateSpec, ensure_pinned_map};
use crate::landscape::pin_and_reuse_map;
use crate::LandscapeMapPath;
static BIND_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
const CONFIG: MapCreateSpec = MapCreateSpec { map_type: MapType::Array,
    name: "dpi_rt_cfg_v1", key_size: 4, value_size: 16, max_entries: 1,
    map_flags: libbpf_sys::BPF_F_RDONLY_PROG, inner: None };
const CLIENTS: MapCreateSpec = MapCreateSpec { map_type: MapType::Hash,
    name: "dpi_rt_cli_v1", key_size: 20, value_size: 4, max_entries: 256,
    map_flags: libbpf_sys::BPF_F_RDONLY_PROG, inner: None };
const HINTS: MapCreateSpec = MapCreateSpec { map_type: MapType::Hash,
    name: "dpi_rt_hint_v1", key_size: 40, value_size: 24, max_entries: 65536,
    map_flags: libbpf_sys::BPF_F_RDONLY_PROG, inner: None };
const FLOWS: MapCreateSpec = MapCreateSpec { map_type: MapType::Hash,
    name: "dpi_rt_flow_v1", key_size: 40, value_size: 96, max_entries: 65536,
    map_flags: 0, inner: None };
const NAT_READY: MapCreateSpec = MapCreateSpec { map_type: MapType::Hash,
    name: "dpi_rt_nat_v1", key_size: 4, value_size: 16, max_entries: 1024,
    map_flags: libbpf_sys::BPF_F_RDONLY_PROG, inner: None };

pub(crate) fn bind(paths: &LandscapeMapPath, cfg: &mut OpenMapMut<'_>,
    clients: &mut OpenMapMut<'_>, hints: &mut OpenMapMut<'_>, flows: &mut OpenMapMut<'_>, nat_ready: &mut OpenMapMut<'_>) -> LdEbpfResult<()> {
    let _guard = BIND_LOCK.lock().expect("DPI routing initialization lock");
    fn bind_one(paths: &LandscapeMapPath, spec: &MapCreateSpec, map: &mut OpenMapMut<'_>) -> LdEbpfResult<()> {
        let path = paths.root.join(spec.name);
        ensure_pinned_map(spec, &path)?;
        pin_and_reuse_map(map, &path)?;
        Ok(())
    }
    bind_one(paths, &CONFIG, cfg)?;
    bind_one(paths, &CLIENTS, clients)?;
    bind_one(paths, &HINTS, hints)?;
    bind_one(paths, &FLOWS, flows)?;
    bind_one(paths, &NAT_READY, nat_ready)?;
    Ok(())
}
pub(crate) fn nat_ready(paths: &LandscapeMapPath, chain: u16, iface: u32, addr: u32) -> LdEbpfResult<u64> {
    use libbpf_rs::{MapCore, MapFlags, MapHandle};
    let _guard = BIND_LOCK.lock().expect("DPI NAT registry lock");
    let map = MapHandle::from_pinned_path(paths.root.join(NAT_READY.name))?;
    let mut epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .expect("system wall clock before epoch").as_nanos() as u64;
    if let Some(previous) = map.lookup(&u32::from(chain).to_ne_bytes(), MapFlags::ANY)? {
        if previous.len() == 16 {
            epoch = epoch.max(u64::from_ne_bytes(previous[8..16].try_into().unwrap()).saturating_add(1));
        }
    }
    let mut value = [0u8; 16];
    value[..4].copy_from_slice(&iface.to_ne_bytes());
    value[4..8].copy_from_slice(&addr.to_ne_bytes());
    value[8..].copy_from_slice(&epoch.to_ne_bytes());
    map.update(&u32::from(chain).to_ne_bytes(), &value, MapFlags::ANY)?;
    Ok(epoch)
}
pub(crate) fn nat_ready_remove(paths: &LandscapeMapPath, chain: u16, epoch: u64) -> LdEbpfResult<()> {
    use libbpf_rs::{MapCore, MapFlags, MapHandle};
    let _guard = BIND_LOCK.lock().expect("DPI NAT registry lock");
    let map = MapHandle::from_pinned_path(paths.root.join(NAT_READY.name))?;
    let key = u32::from(chain).to_ne_bytes();
    if let Some(value) = map.lookup(&key, MapFlags::ANY)? {
        if value.len() == 16 && value[8..] == epoch.to_ne_bytes() { map.delete(&key)?; }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use libbpf_rs::skel::SkelBuilder as _;
    #[test]
    fn routing_map_abi_matches_c_skeleton() {
        let mut obj = std::mem::MaybeUninit::uninit();
        let builder = crate::skel::tc_lan_ingress_route::TcLanIngressRouteSkelBuilder::default();
        let open = builder.open(&mut obj).expect("open patched LAN skeleton");
        crate::maps::assert_skel_map_matches(&open.maps.dpi_rt_cfg_v1, &CONFIG);
        crate::maps::assert_skel_map_matches(&open.maps.dpi_rt_cli_v1, &CLIENTS);
        crate::maps::assert_skel_map_matches(&open.maps.dpi_rt_hint_v1, &HINTS);
        crate::maps::assert_skel_map_matches(&open.maps.dpi_rt_flow_v1, &FLOWS);
    }
}
