#ifndef LD_DPI_METADATA_V1_H
#define LD_DPI_METADATA_V1_H

/* Observation-only ABI v1. No skb mark, route, NAT, verdict or packet mutation.
 * Addresses and ports are network byte order; all other integers are native.
 * Counters start after a classifier has installed an unexpired label.
 */
#include "dpi/flow_abi.h"
struct dpi_label_v1 {
    __u64 expires_ns;
    __u64 generation;
    __u32 appid;
    __u32 rule_id;
    __u32 qos_class; /* Metadata only; never applied to the packet here. */
    __u32 reserved;
};
struct dpi_count_key_v1 {
    struct dpi_flow_key_v1 flow;
    __u64 generation;
};
struct dpi_count_v1 {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen_ns;
};
_Static_assert(sizeof(struct dpi_flow_key_v1) == 40, "DPI key ABI");
_Static_assert(sizeof(struct dpi_label_v1) == 32, "DPI label ABI");
_Static_assert(sizeof(struct dpi_count_key_v1) == 48, "DPI counter key ABI");
_Static_assert(sizeof(struct dpi_count_v1) == 24, "DPI counter ABI");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_RDONLY_PROG);
    __type(key, struct dpi_flow_key_v1);
    __type(value, struct dpi_label_v1);
} dpi_labels_v1 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dpi_count_key_v1);
    __type(value, struct dpi_count_v1);
} dpi_counts_v1 SEC(".maps");

/* Deliberately skips fragments, IPv6 extension headers, non-TCP/UDP and
 * non-linear/truncated headers. Unsupported observations never change routing.
 * l3_offset is 0 or 14 at the Landscape call sites; VLAN is handled upstream.
 */
static __always_inline int dpi_key_from_packet(const void *data, const void *end,
                                              __u32 l3_offset, __u8 version,
                                              struct dpi_flow_key_v1 *key) {
    const __u8 *ip = (const __u8 *)data + l3_offset;
    const __u8 *ports;
    __u32 hdr_len, ip_len;
    __u8 protocol;
    if (version == 4) {
        if ((const void *)(ip + 20) > end || (ip[0] >> 4) != 4) return 0;
        hdr_len = (ip[0] & 15) * 4;
        if (hdr_len < 20 || hdr_len > 60 || (ip[6] & 0x3f) || ip[7]) return 0;
        protocol = ip[9];
        ip_len = ((__u32)ip[2] << 8) | ip[3];
        __builtin_memcpy(key->src, ip + 12, 4);
        __builtin_memcpy(key->dst, ip + 16, 4);
    } else if (version == 6) {
        if ((const void *)(ip + 40) > end || (ip[0] >> 4) != 6) return 0;
        hdr_len = 40;
        protocol = ip[6];
        ip_len = 40 + (((__u32)ip[4] << 8) | ip[5]);
        __builtin_memcpy(key->src, ip + 8, 16);
        __builtin_memcpy(key->dst, ip + 24, 16);
    } else return 0;
    if (protocol != 6 && protocol != 17) return 0;
    ports = ip + hdr_len;
    if (protocol == 6) {
        if (ip_len < hdr_len + 20 || (const void *)(ports + 20) > end) return 0;
    } else {
        if (ip_len < hdr_len + 8 || (const void *)(ports + 8) > end) return 0;
    }
    key->ip_version = version;
    key->protocol = protocol;
    __builtin_memcpy(&key->sport, ports, 2);
    __builtin_memcpy(&key->dport, ports + 2, 2);
    return 1;
}

static __always_inline void dpi_observe_bytes(const void *data, const void *end,
                                               __u32 l3_offset, __u8 version,
                                               __u32 packet_bytes) {
    struct dpi_flow_key_v1 key = {};
    if (!dpi_key_from_packet(data, end, l3_offset, version, &key)) return;
    const struct dpi_label_v1 *label = bpf_map_lookup_elem(&dpi_labels_v1, &key);
    if (!label || !label->appid) return;
    __u64 now = bpf_ktime_get_ns();
    if (now >= label->expires_ns) return;
    struct dpi_count_key_v1 count_key = {.flow = key, .generation = label->generation};
    struct dpi_count_v1 *counter = bpf_map_lookup_elem(&dpi_counts_v1, &count_key);
    if (!counter) {
        struct dpi_count_v1 initial = {};
        bpf_map_update_elem(&dpi_counts_v1, &count_key, &initial, BPF_NOEXIST);
        counter = bpf_map_lookup_elem(&dpi_counts_v1, &count_key);
    }
    if (counter) {
        __sync_fetch_and_add(&counter->packets, 1);
        __sync_fetch_and_add(&counter->bytes, packet_bytes);
        counter->last_seen_ns = now;
    }
}

static __always_inline void dpi_observe_tc(struct __sk_buff *skb, __u32 offset,
                                          __u8 version, bool xdp_enabled) {
    /* In XDP-enabled mode the XDP ingress already observed this packet before
     * any TC handoff. Counting in both paths would double-count slow packets. */
    if (xdp_enabled) return;
    dpi_observe_bytes((void *)(long)skb->data, (void *)(long)skb->data_end,
                      offset, version, skb->len);
}
static __always_inline void dpi_observe_xdp(struct xdp_md *ctx, __u8 version) {
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    dpi_observe_bytes(data, end, 14, version, (__u32)(end - data));
}
#endif
