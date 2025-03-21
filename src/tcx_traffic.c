#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF

struct traffic_stats {
    __u64 rx_bytes;
    __u64 rx_packets;
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, struct traffic_stats);
} stats_map SEC(".maps");

SEC("xdp")
int xdp_traffic_monitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 解析以太网头
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) return XDP_PASS;

    // 处理 IPv4 或 IPv6 流量
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        // IPv4 处理逻辑
        struct iphdr *ip = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip) > data_end) return XDP_PASS;

        // 跳过分片报文
        if (ip->frag_off & bpf_htons(IP_MF | IP_OFFSET)) return XDP_PASS;

        // 仅处理 TCP 流量
        if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

        // 计算 IP 头长度
        unsigned int ip_header_len = ip->ihl * 4;
        struct tcphdr *tcp = (void *)ip + ip_header_len;
        if ((void *)tcp + sizeof(*tcp) > data_end) return XDP_PASS;

        // 获取目标端口
        __u16 dest_port = bpf_ntohs(tcp->dest);
        if (dest_port != 8080) return XDP_PASS;

        // 更新统计信息
        struct traffic_stats *stats = bpf_map_lookup_elem(&stats_map, &dest_port);
        if (!stats) {
            struct traffic_stats new_stats = {
                .rx_bytes = ctx->data_end - ctx->data,
                .rx_packets = 1,
            };
            bpf_map_update_elem(&stats_map, &dest_port, &new_stats, BPF_ANY);
        } else {
            stats->rx_bytes += ctx->data_end - ctx->data;
            stats->rx_packets++;
        }
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        // IPv6 处理逻辑
        struct ipv6hdr *ip6 = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*ip6) > data_end) return XDP_PASS;

        // 仅处理 TCP 流量
        if (ip6->nexthdr != IPPROTO_TCP) return XDP_PASS;

        // 解析 TCP 头
        struct tcphdr *tcp = (void *)ip6 + sizeof(*ip6);
        if ((void *)tcp + sizeof(*tcp) > data_end) return XDP_PASS;

        // 获取目标端口
        __u16 dest_port = bpf_ntohs(tcp->dest);
        if (dest_port != 8080) return XDP_PASS;

        // 更新统计信息
        struct traffic_stats *stats = bpf_map_lookup_elem(&stats_map, &dest_port);
        if (!stats) {
            struct traffic_stats new_stats = {
                .rx_bytes = ctx->data_end - ctx->data,
                .rx_packets = 1,
            };
            bpf_map_update_elem(&stats_map, &dest_port, &new_stats, BPF_ANY);
        } else {
            stats->rx_bytes += ctx->data_end - ctx->data;
            stats->rx_packets++;
        }
    } else {
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";