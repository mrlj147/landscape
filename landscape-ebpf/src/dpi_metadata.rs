//! Observation-only DPI maps. Kept separate from routing/NAT/Flow maps.
use libbpf_rs::{MapType, OpenMapMut, libbpf_sys};
use crate::bpf_error::LdEbpfResult;
use crate::maps::{MapCreateSpec, ensure_pinned_map};
use crate::landscape::pin_and_reuse_map;
use crate::LandscapeMapPath;
static BIND_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const LABELS: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LruHash, name: "dpi_labels_v1", key_size: 40,
    value_size: 32, max_entries: 65536,
    map_flags: libbpf_sys::BPF_F_RDONLY_PROG, inner: None,
};
const COUNTS: MapCreateSpec = MapCreateSpec {
    map_type: MapType::LruHash, name: "dpi_counts_v1", key_size: 48,
    value_size: 24, max_entries: 65536, map_flags: 0, inner: None,
};

pub(crate) fn bind(paths: &LandscapeMapPath, labels: &mut OpenMapMut<'_>,
                   counts: &mut OpenMapMut<'_>) -> LdEbpfResult<()> {
    let _guard = BIND_LOCK.lock().expect("DPI map initialization lock");
    let labels_path = paths.root.join(LABELS.name);
    let counts_path = paths.root.join(COUNTS.name);
    ensure_pinned_map(&LABELS, &labels_path)?;
    ensure_pinned_map(&COUNTS, &counts_path)?;
    pin_and_reuse_map(labels, &labels_path)?;
    pin_and_reuse_map(counts, &counts_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libbpf_rs::skel::SkelBuilder as _;
    #[test]
    fn metadata_map_abi_matches_c_skeleton() {
        let mut obj = std::mem::MaybeUninit::uninit();
        let builder = crate::skel::tc_lan_ingress_route::TcLanIngressRouteSkelBuilder::default();
        let open = builder.open(&mut obj).expect("open patched LAN skeleton");
        crate::maps::assert_skel_map_matches(&open.maps.dpi_labels_v1, &LABELS);
        crate::maps::assert_skel_map_matches(&open.maps.dpi_counts_v1, &COUNTS);
    }
}
