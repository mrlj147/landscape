#ifndef LD_DPI_ROUTING_V1_H
#define LD_DPI_ROUTING_V1_H
#include "dpi/metadata.h"

/* Separate connection decisions, never the upstream IP-pair cache or NAT maps.
 * No LRU eviction or label-TTL expiry: those could move an established session.
 * ABI integers native endian; addresses/ports network endian. */
#include "dpi/routing_maps.h"
/* Pending NAT failures are bounded without guessing established lifetimes.
 * CAS claims retirement; a concurrent NAT bind must then reject its packet. */
static int dpi_pending_expire(void *map, struct dpi_flow_key_v1 *key,
                               struct dpi_rt_decision *value) {
    __u32 chain = value->target.chain_id;
    const struct dpi_rt_nat_ready *ready = bpf_map_lookup_elem(&dpi_rt_nat_v1, &chain);
    __u64 token = value->nat_token;
    if (!token || !ready || ready->epoch != value->nat_epoch || ready->ifindex != value->target.ifindex) {
        if (token != DPI_ROUTE_RETIRING &&
            __sync_val_compare_and_swap(&value->nat_token, token, DPI_ROUTE_RETIRING) == token)
            bpf_map_delete_elem(&dpi_rt_flow_v1, key);
    } else {
        bpf_timer_start(&value->pending_timer, 30000000000ULL, 0);
    }
    return 0;
}
/* Keep the TC path selected even when the producer dies or its lease expires:
 * existing connections still need their pinned decisions. */
static __always_inline int dpi_routing_armed(void) {
    __u32 zero = 0;
    const struct dpi_rt_config *cfg = bpf_map_lookup_elem(&dpi_rt_cfg_v1, &zero);
    return cfg && cfg->armed == 1;
}
static __always_inline int dpi_routing_admitting(__u64 now) {
    __u32 zero = 0;
    const struct dpi_rt_config *cfg = bpf_map_lookup_elem(&dpi_rt_cfg_v1, &zero);
    return cfg && cfg->armed && cfg->admit && cfg->lease_ns > now;
}
static __always_inline int dpi_routing_client(const struct dpi_flow_key_v1 *key) {
    struct dpi_rt_client client = {.version = key->ip_version};
    __builtin_memcpy(client.addr, key->src, 16);
    const __u32 *approved = bpf_map_lookup_elem(&dpi_rt_cli_v1, &client);
    return approved && *approved == 1;
}
/* Only TCP SYN without ACK qualifies as a newly observed TCP connection.
 * UDP is admitted only when hints explicitly approve its endpoint heuristic;
 * deployment requires selected clients to be quiescent at initial arm time. */
static __always_inline int dpi_route_packet_key(const void *data, const void *end,
             __u32 l3, __u8 version, struct dpi_flow_key_v1 *key, __u32 *seq) {
    if (!dpi_key_from_packet(data, end, l3, version, key)) return -1;
    if (key->protocol == 17) return 1;
    const __u8 *ip = (const __u8 *)data + l3;
    __u32 hdr = version == 4 ? (ip[0] & 15) * 4 : 40;
    const __u8 *tcp = ip + hdr;
    if ((const void *)(tcp + 20) > end) return -1;
    __builtin_memcpy(seq, tcp + 4, 4);
    return (tcp[13] & 0x17) == 0x02; /* SYN, no ACK/FIN/RST */
}
/* Endpoint hints deliberately omit only source port; they are suggestions for
 * future connections, not evidence that every connection at an IP is this app.
 * flags bit0 explicitly permits the UDP new-endpoint heuristic. */
static __always_inline __u32 dpi_route_hint(const struct dpi_flow_key_v1 *key,
                                           __u64 now, __u32 *appid) {
    __u32 zero = 0;
    const struct dpi_rt_config *cfg = bpf_map_lookup_elem(&dpi_rt_cfg_v1, &zero);
    if (!cfg || !cfg->armed || !cfg->admit || cfg->lease_ns <= now) return 0;
    struct dpi_flow_key_v1 endpoint = *key;
    endpoint.sport = 0;
    const struct dpi_rt_hint *hint = bpf_map_lookup_elem(&dpi_rt_hint_v1, &endpoint);
    if (!hint || !hint->appid || hint->expires_ns <= now || !hint->flow_id || hint->flow_id > 255)
        return 0;
    if (key->protocol == 17 && !(hint->flags & 1)) return 0;
    *appid = hint->appid;
    return hint->flow_id;
}
#endif
