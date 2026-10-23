#ifndef LD_DPI_FLOW_ABI_V1_H
#define LD_DPI_FLOW_ABI_V1_H
struct dpi_flow_key_v1 {
    __u8 ip_version;
    __u8 protocol;
    __u16 reserved;
    __u8 src[16];
    __u8 dst[16];
    __be16 sport;
    __be16 dport;
};
#endif
