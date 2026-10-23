#ifndef LD_DPI_ROUTING_MAPS_V1_H
#define LD_DPI_ROUTING_MAPS_V1_H
#include "dpi/flow_abi.h"
struct dpi_rt_client { __u32 version; __u8 addr[16]; };
struct dpi_rt_config { __u32 armed; __u32 admit; __u64 lease_ns; };
struct dpi_rt_hint { __u64 expires_ns; __u32 appid; __u32 flow_id; __u32 flags; __u32 reserved; };
struct dpi_rt_target {
    __u32 ifindex;
    __u8 gateway[16];
    __u8 mac[6];
    __u8 has_mac;
    __u8 is_docker;
    __u16 chain_id;
    __u16 reserved;
};
struct dpi_rt_decision {
    __u64 created_ns;
    __u64 last_seen_ns;
    __u32 mark;
    __u32 appid;
    __u64 nat_token;
    __u32 initial_seq;
    __u32 flags;
    __u64 nat_epoch;
    struct dpi_rt_target target;
    struct bpf_timer pending_timer;
};
_Static_assert(sizeof(struct dpi_rt_client) == 20, "route client ABI");
_Static_assert(sizeof(struct dpi_rt_hint) == 24, "route hint ABI");
_Static_assert(sizeof(struct dpi_rt_config) == 16, "route config ABI");
_Static_assert(sizeof(struct dpi_rt_target) == 32, "route target ABI");
_Static_assert(sizeof(struct dpi_rt_decision) == 96, "route decision ABI");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __uint(map_flags, BPF_F_RDONLY_PROG);
    __type(key, __u32); __type(value, struct dpi_rt_config);
} dpi_rt_cfg_v1 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256);
    __uint(map_flags, BPF_F_RDONLY_PROG);
    __type(key, struct dpi_rt_client); __type(value, __u32);
} dpi_rt_cli_v1 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_RDONLY_PROG);
    __type(key, struct dpi_flow_key_v1); __type(value, struct dpi_rt_hint);
} dpi_rt_hint_v1 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536);
    __type(key, struct dpi_flow_key_v1); __type(value, struct dpi_rt_decision);
} dpi_rt_flow_v1 SEC(".maps");

struct dpi_rt_nat_ready { __u32 ifindex; __u32 addr; __u64 epoch; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_RDONLY_PROG);
    __type(key, __u32); __type(value, struct dpi_rt_nat_ready);
} dpi_rt_nat_v1 SEC(".maps");
#define DPI_ROUTE_RETIRING (~(__u64)0)
#endif
