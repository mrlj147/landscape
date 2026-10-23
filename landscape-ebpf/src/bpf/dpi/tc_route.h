#ifndef LD_DPI_TC_ROUTE_V1_H
#define LD_DPI_TC_ROUTE_V1_H
#include "dpi/routing.h"

/* Return TC_ACT_OK only to continue the original route path. Real decisions
 * use the original Landscape redirect helpers: MAC/PPP chain/NAT stay owned
 * by Landscape. No writes to rt*_cache_map, NAT or Linux conntrack marks. */
static __always_inline int dpi_route4_tc(struct __sk_buff *skb, __u32 l3,
                 const struct route4_context *context, __u32 mark) {
    if (!dpi_routing_armed() || is_host_direct(mark)) return TC_ACT_OK;
    struct dpi_flow_key_v1 key = {};
    key.ip_version = 4;
    __builtin_memcpy(key.src, &context->saddr, 4);
    if (!dpi_routing_client(&key)) return TC_ACT_OK;
    __u8 header[20];
    if (bpf_skb_load_bytes(skb, l3, header, sizeof(header))) return TC_ACT_SHOT;
    if ((header[6] & 0x3f) || header[7]) return TC_ACT_SHOT; /* No fragment may fall onto another WAN. */
    if (header[9] != 6 && header[9] != 17) return TC_ACT_OK;
    __u32 seq = 0;
    int fresh = dpi_route_packet_key((void *)(long)skb->data, (void *)(long)skb->data_end,
                                    l3, 4, &key, &seq);
    if (fresh < 0) return TC_ACT_SHOT;
    __u64 now = bpf_ktime_get_ns();
    struct dpi_rt_decision *stored = bpf_map_lookup_elem(&dpi_rt_flow_v1, &key);
    if (!stored) {
        if (!fresh) return TC_ACT_OK;
        struct dpi_rt_decision candidate = {.created_ns = bpf_ktime_get_tai_ns(), .last_seen_ns = now,
                                            .mark = mark, .initial_seq = seq};
        if (get_flow_action(mark) == FLOW_KEEP_GOING) {
            __u32 appid = 0, flow = dpi_route_hint(&key, now, &appid);
            if (flow) { candidate.mark = replace_flow_id(mark, flow); candidate.appid = appid; }
        }
        struct route4_slot_key slot = {.flow_id = get_flow_id(candidate.mark),
                                      .slot = route4_target_slot(context->daddr)};
        struct route4_target_info *target = bpf_map_lookup_elem(&rt4_slot_map, &slot);
        /* An unavailable approved WAN cannot silently fall through to another WAN. */
        if (!target || !target->ifindex) return TC_ACT_SHOT;
        if (target->is_docker) return candidate.appid ? TC_ACT_SHOT : TC_ACT_OK;
        __u32 nat_chain = target->link_chain_id;
        const struct dpi_rt_nat_ready *nat_ready = bpf_map_lookup_elem(&dpi_rt_nat_v1, &nat_chain);
        if (!nat_ready || nat_ready->ifindex != target->ifindex) return TC_ACT_SHOT;
        candidate.target.ifindex = target->ifindex;
        __builtin_memcpy(candidate.target.gateway, &target->gate_addr, 4);
        __builtin_memcpy(candidate.target.mac, target->mac, 6);
        candidate.nat_epoch = nat_ready->epoch;
        __u32 nat_addr = nat_ready->addr;
        __builtin_memcpy(candidate.target.gateway + 4, &nat_addr, 4);
        candidate.target.has_mac = target->has_mac;
        candidate.target.chain_id = target->link_chain_id;
        /* Capacity/concurrent insert failure: never apply an unpinned decision. */
        int inserted = bpf_map_update_elem(&dpi_rt_flow_v1, &key, &candidate, BPF_NOEXIST);
        stored = bpf_map_lookup_elem(&dpi_rt_flow_v1, &key);
        if (!stored) return TC_ACT_SHOT; /* Never transmit an unpinned controlled connection. */
        if (!inserted) {
            if (bpf_timer_init(&stored->pending_timer, &dpi_rt_flow_v1, 1) ||
                bpf_timer_set_callback(&stored->pending_timer, dpi_pending_expire) ||
                bpf_timer_start(&stored->pending_timer, 30000000000ULL, 0)) {
                if (__sync_val_compare_and_swap(&stored->nat_token, 0, DPI_ROUTE_RETIRING) == 0)
                    bpf_map_delete_elem(&dpi_rt_flow_v1, &key);
                return TC_ACT_SHOT;
            }
        }
    }
    if (stored->nat_token == DPI_ROUTE_RETIRING) return TC_ACT_SHOT;
    struct dpi_rt_target chosen = stored->target;
    __u32 chosen_mark = stored->mark;
    __u64 chosen_epoch = stored->nat_epoch;
    stored->last_seen_ns = now;
    __u32 chosen_chain = chosen.chain_id, chosen_nat_addr = 0;
    __builtin_memcpy(&chosen_nat_addr, chosen.gateway + 4, 4);
    const struct dpi_rt_nat_ready *ready = bpf_map_lookup_elem(&dpi_rt_nat_v1, &chosen_chain);
    if (!ready || ready->ifindex != chosen.ifindex || ready->addr != chosen_nat_addr || ready->epoch != chosen_epoch)
        return TC_ACT_SHOT;
    struct route4_slot_key slot = {.flow_id = get_flow_id(chosen_mark),
                                  .slot = route4_target_slot(context->daddr)};
    struct route4_target_info *live = bpf_map_lookup_elem(&rt4_slot_map, &slot);
    __be32 gateway = 0;
    __builtin_memcpy(&gateway, chosen.gateway, 4);
    /* Fail closed if topology changed. Never move an existing NAT session. */
    if (!live || live->ifindex != chosen.ifindex || live->link_chain_id != chosen.chain_id
        || live->gate_addr != gateway || live->is_docker || live->has_mac != chosen.has_mac)
        return TC_ACT_SHOT;
    struct route4_cache_value target = {.mark_value = chosen_mark,
        .ifindex = chosen.ifindex, .gate_addr = gateway,
        .has_mac = chosen.has_mac, .link_chain_id = chosen.chain_id};
    __builtin_memcpy(target.mac, live->mac, 6); /* Same WAN, refreshed L2 address. */
    skb_set_mark(skb, chosen_mark);
    return route4_redirect_by_cached_target(skb, l3, &target);
}
static __always_inline int dpi_route6_tc(struct __sk_buff *skb, __u32 l3,
                 const struct route6_context *context, __u32 mark) {
    /* Dual-ISP IPv6 source-prefix policy is not inferred from an AppID. */
    return TC_ACT_OK;
}
#endif
