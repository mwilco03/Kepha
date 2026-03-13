/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Gatekeeper XDP shared header — defines map keys, values, and constants
 * shared between BPF programs and Go user-space code.
 *
 * This header is the single source of truth for data layout. The Go
 * types in internal/xdp/ must match these struct definitions exactly.
 */

#ifndef __GATEKEEPER_H__
#define __GATEKEEPER_H__

/* Tail call program indices in the PROG_ARRAY map. */
#define PROG_BLOCKLIST  0  /* IPv4 blocklist lookup */
#define PROG_BLOCKLIST6 1  /* IPv6 blocklist lookup */
#define PROG_ACL        2  /* Simple ACL check */
#define PROG_ACCOUNTING 3  /* Traffic accounting */
#define PROG_MAX        4

/* Statistics map key (per-interface, per-action). */
struct stats_key {
    __u32 ifindex;
    __u32 action; /* XDP_DROP=1, XDP_PASS=2, etc. */
};

/* Statistics map value (per-CPU). */
struct stats_value {
    __u64 packets;
    __u64 bytes;
};

/* Blocklist map value — just a marker (1 = blocked). */
struct blocklist_value {
    __u8 blocked;
    __u8 _pad[3];
};

/* ACL rule for the fast-path map. */
struct acl_rule {
    __u32 src_ip;      /* Network byte order, 0 = any */
    __u32 src_mask;    /* Network byte order */
    __u32 dst_ip;      /* Network byte order, 0 = any */
    __u32 dst_mask;    /* Network byte order */
    __u8  protocol;    /* IPPROTO_TCP=6, IPPROTO_UDP=17, 0=any */
    __u8  action;      /* XDP_DROP=1, XDP_PASS=2 */
    __u16 dst_port;    /* Host byte order, 0 = any */
};

/* Parsed packet metadata passed between tail-called programs via per-CPU map. */
struct pkt_meta {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;    /* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP */
    __u8  ip_version;  /* 4 or 6 */
    __u16 pkt_len;
};

/* Maximum entries for maps. */
#define MAX_BLOCKLIST_ENTRIES  1000000
#define MAX_BLOCKLIST6_ENTRIES 100000
#define MAX_ACL_RULES          4096
#define MAX_CPUS               128

#endif /* __GATEKEEPER_H__ */
