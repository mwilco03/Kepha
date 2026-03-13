// SPDX-License-Identifier: GPL-2.0-only
//
// Gatekeeper XDP program — pre-stack packet processing.
//
// Architecture:
//   1. Entry program: parse Ethernet + IP headers, populate pkt_meta
//   2. Tail call → blocklist: check source IP against blocklist map
//   3. Tail call → ACL: check against simplified ACL rules
//   4. Tail call → accounting: update per-interface packet/byte counters
//   5. Default: XDP_PASS (send to kernel stack / nftables)
//
// FAIL-OPEN: On any error (map miss, tail call failure), we XDP_PASS.
// This ensures legitimate traffic is never silently dropped by a bug.
//
// Build: clang -O2 -g -target bpf -c gatekeeper_xdp.c -o gatekeeper_xdp.o
//        or via bpf2go: //go:generate go run github.com/cilium/ebpf/cmd/bpf2go ...

#include "vmlinux.h"  // Generated from BTF, provides all kernel types.
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "gatekeeper.h"

// ── Maps ────────────────────────────────────────────────────────────

// Tail-call program array — allows chaining XDP programs.
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, PROG_MAX);
    __type(key, __u32);
    __type(value, __u32);
} gk_progs SEC(".maps");

// Per-CPU metadata passed between tail-called programs.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pkt_meta);
} gk_meta SEC(".maps");

// IPv4 blocklist: src_ip (network order) → blocked flag.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_BLOCKLIST_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct { __u32 prefixlen; __u32 addr; });
    __type(value, struct blocklist_value);
} gk_blocklist SEC(".maps");

// IPv6 blocklist: src_ip (network order) → blocked flag.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_BLOCKLIST6_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct { __u32 prefixlen; __u32 addr[4]; });
    __type(value, struct blocklist_value);
} gk_blocklist6 SEC(".maps");

// Per-CPU statistics: (ifindex, action) → (packets, bytes).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_CPUS * 4); // 4 actions per CPU
    __type(key, struct stats_key);
    __type(value, struct stats_value);
} gk_stats SEC(".maps");

// ACL rules array.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_ACL_RULES);
    __type(key, __u32);
    __type(value, struct acl_rule);
} gk_acls SEC(".maps");

// ACL rule count (single-element array for atomic read).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} gk_acl_count SEC(".maps");

// ── Helpers ─────────────────────────────────────────────────────────

static __always_inline void update_stats(__u32 ifindex, __u32 action, __u64 bytes) {
    struct stats_key key = { .ifindex = ifindex, .action = action };
    struct stats_value *val = bpf_map_lookup_elem(&gk_stats, &key);
    if (val) {
        val->packets += 1;
        val->bytes += bytes;
    } else {
        struct stats_value new_val = { .packets = 1, .bytes = bytes };
        bpf_map_update_elem(&gk_stats, &key, &new_val, BPF_ANY);
    }
}

// ── Entry Program ───────────────────────────────────────────────────

// gk_entry: Parse packet headers, populate metadata, chain to blocklist.
SEC("xdp")
int gk_entry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet header.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    // Handle VLAN tags (802.1Q).
    void *l3 = (void *)(eth + 1);
    if (eth_proto == 0x8100 || eth_proto == 0x88a8) {
        struct vlan_hdr *vlan = l3;
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;
        eth_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        l3 = (void *)(vlan + 1);
    }

    // Populate metadata.
    __u32 zero = 0;
    struct pkt_meta *meta = bpf_map_lookup_elem(&gk_meta, &zero);
    if (!meta)
        return XDP_PASS; // Can't happen for PERCPU_ARRAY, but verifier needs it.

    meta->pkt_len = (__u16)(data_end - data);

    if (eth_proto == 0x0800) {
        // IPv4.
        struct iphdr *ip = l3;
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        meta->ip_version = 4;
        meta->src_ip = ip->saddr;
        meta->dst_ip = ip->daddr;
        meta->protocol = ip->protocol;

        // Parse L4 ports.
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
            if ((void *)(tcp + 1) > data_end)
                goto tail_blocklist;
            meta->src_port = bpf_ntohs(tcp->source);
            meta->dst_port = bpf_ntohs(tcp->dest);
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + (ip->ihl * 4);
            if ((void *)(udp + 1) > data_end)
                goto tail_blocklist;
            meta->src_port = bpf_ntohs(udp->source);
            meta->dst_port = bpf_ntohs(udp->dest);
        }

    } else if (eth_proto == 0x86DD) {
        // IPv6.
        struct ipv6hdr *ip6 = l3;
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        meta->ip_version = 6;
        // Store first 4 bytes of src/dst for quick blocklist check.
        meta->src_ip = ip6->saddr.in6_u.u6_addr32[0];
        meta->dst_ip = ip6->daddr.in6_u.u6_addr32[0];
        meta->protocol = ip6->nexthdr;

    } else {
        // Not IP — pass through (ARP, etc.).
        return XDP_PASS;
    }

tail_blocklist:
    // Chain to blocklist check.
    bpf_tail_call(ctx, &gk_progs, PROG_BLOCKLIST);
    // If tail call fails, fall through to PASS.
    update_stats(ctx->ingress_ifindex, XDP_PASS, meta->pkt_len);
    return XDP_PASS;
}

// ── Blocklist Program ───────────────────────────────────────────────

SEC("xdp")
int gk_blocklist(struct xdp_md *ctx) {
    __u32 zero = 0;
    struct pkt_meta *meta = bpf_map_lookup_elem(&gk_meta, &zero);
    if (!meta)
        return XDP_PASS;

    if (meta->ip_version == 4) {
        // LPM trie lookup for IPv4.
        struct { __u32 prefixlen; __u32 addr; } key = {
            .prefixlen = 32,
            .addr = meta->src_ip,
        };
        struct blocklist_value *val = bpf_map_lookup_elem(&gk_blocklist, &key);
        if (val && val->blocked) {
            update_stats(ctx->ingress_ifindex, XDP_DROP, meta->pkt_len);
            return XDP_DROP;
        }
    }
    // IPv6 blocklist check would go here with gk_blocklist6.

    // Chain to ACL check.
    bpf_tail_call(ctx, &gk_progs, PROG_ACL);
    // Fall through: pass.
    update_stats(ctx->ingress_ifindex, XDP_PASS, meta->pkt_len);
    return XDP_PASS;
}

// ── ACL Program ─────────────────────────────────────────────────────

SEC("xdp")
int gk_acl(struct xdp_md *ctx) {
    __u32 zero = 0;
    struct pkt_meta *meta = bpf_map_lookup_elem(&gk_meta, &zero);
    if (!meta)
        return XDP_PASS;

    // Read ACL rule count.
    __u32 *count_ptr = bpf_map_lookup_elem(&gk_acl_count, &zero);
    __u32 count = count_ptr ? *count_ptr : 0;

    // Cap to prevent unbounded loops (BPF verifier constraint).
    if (count > 256)
        count = 256;

    // Iterate ACL rules.
    for (__u32 i = 0; i < count; i++) {
        struct acl_rule *rule = bpf_map_lookup_elem(&gk_acls, &i);
        if (!rule)
            break;

        // Match source IP (if specified).
        if (rule->src_ip != 0) {
            if ((meta->src_ip & rule->src_mask) != (rule->src_ip & rule->src_mask))
                continue;
        }

        // Match destination IP (if specified).
        if (rule->dst_ip != 0) {
            if ((meta->dst_ip & rule->dst_mask) != (rule->dst_ip & rule->dst_mask))
                continue;
        }

        // Match protocol (if specified).
        if (rule->protocol != 0 && rule->protocol != meta->protocol)
            continue;

        // Match destination port (if specified).
        if (rule->dst_port != 0 && rule->dst_port != meta->dst_port)
            continue;

        // Rule matched — apply action.
        if (rule->action == XDP_DROP) {
            update_stats(ctx->ingress_ifindex, XDP_DROP, meta->pkt_len);
            return XDP_DROP;
        }
        // XDP_PASS or other: continue to accounting.
        break;
    }

    // Chain to accounting.
    bpf_tail_call(ctx, &gk_progs, PROG_ACCOUNTING);
    update_stats(ctx->ingress_ifindex, XDP_PASS, meta->pkt_len);
    return XDP_PASS;
}

// ── Accounting Program ──────────────────────────────────────────────

SEC("xdp")
int gk_accounting(struct xdp_md *ctx) {
    __u32 zero = 0;
    struct pkt_meta *meta = bpf_map_lookup_elem(&gk_meta, &zero);
    if (!meta)
        return XDP_PASS;

    update_stats(ctx->ingress_ifindex, XDP_PASS, meta->pkt_len);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
