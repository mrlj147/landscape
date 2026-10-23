#ifndef LD_DPI_NAT_LIFECYCLE_V1_H
#define LD_DPI_NAT_LIFECYCLE_V1_H
#include "dpi/routing_maps.h"
/* Included after nat4_timer_{key,value}_v3 definitions. Every WAN shares only
 * the independent route maps; its original NAT maps remain owned by its chain.
 * A route is retired only when that exact native CT lifetime ends. */
static __always_inline void dpi_nat4_key(const struct nat4_timer_key *ct,
           const struct nat4_timer_value_v3 *value, struct dpi_flow_key_v1 *key) {
    key->ip_version = 4; key->protocol = ct->l4proto;
    __builtin_memcpy(key->src, &value->client_addr.addr, 4);
    __builtin_memcpy(key->dst, &ct->pair_ip.src_addr.addr, 4);
    key->sport = value->client_port;
    key->dport = ct->pair_ip.src_port;
}
static __always_inline int dpi_nat4_bind(const struct nat4_timer_key *ct,
                                          const struct nat4_timer_value_v3 *value) {
    if (ct->l4proto != 6 && ct->l4proto != 17) return 1;
    struct dpi_flow_key_v1 key = {};
    dpi_nat4_key(ct, value, &key);
    struct dpi_rt_decision *route = bpf_map_lookup_elem(&dpi_rt_flow_v1, &key);
    if (!route) {
        __u32 zero = 0;
        const struct dpi_rt_config *cfg = bpf_map_lookup_elem(&dpi_rt_cfg_v1, &zero);
        struct dpi_rt_client client = {.version = 4};
        __builtin_memcpy(client.addr, key.src, 16);
        const __u32 *controlled = bpf_map_lookup_elem(&dpi_rt_cli_v1, &client);
        /* A retired pending decision must not be followed by a late NAT send. */
        return !(cfg && cfg->armed && controlled && *controlled == 1);
    }
    if (route->target.ifindex != value->ifindex || (route->mark & 255) != value->flow_id)
        return 0;
    /* TAI timestamps identify admission and native CT lifetime on the same host.
     * A late old packet cannot bind a freshly reused tuple to its older CT. */
    if (value->create_time < route->created_ns) return 0;
    __u64 old = route->nat_token;
    if (old == DPI_ROUTE_RETIRING || (old && old != value->create_time)) return 0;
    if (old == value->create_time) return 1;
    return __sync_val_compare_and_swap(&route->nat_token, old, value->create_time) == old;
}
static __always_inline void dpi_nat4_retire(const struct nat4_timer_key *ct,
                                            const struct nat4_timer_value_v3 *value) {
    if (ct->l4proto != 6 && ct->l4proto != 17) return;
    struct dpi_flow_key_v1 key = {};
    dpi_nat4_key(ct, value, &key);
    struct dpi_rt_decision *route = bpf_map_lookup_elem(&dpi_rt_flow_v1, &key);
    if (route && route->nat_token && route->nat_token == value->create_time &&
        route->target.ifindex == value->ifindex && (route->mark & 255) == value->flow_id &&
        __sync_val_compare_and_swap(&route->nat_token, value->create_time, DPI_ROUTE_RETIRING) == value->create_time)
        bpf_map_delete_elem(&dpi_rt_flow_v1, &key);
}
#endif
