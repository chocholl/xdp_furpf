#include "vmlinux_local.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp/xdp_helpers.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <asm/errno.h>

#define MAX_RULES 10
#define __u128 __uint128_t

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define        ARPOP_REQUEST        1                /* ARP request.  */
#define        ARPOP_REPLY        2                /* ARP reply.  */
#define        ARPOP_RREQUEST        3                /* RARP request.  */
#define        ARPOP_RREPLY        4                /* RARP reply.  */
#define        ARPOP_InREQUEST        8                /* InARP request.  */
#define        ARPOP_InREPLY        9                /* InARP reply.  */
#define        ARPOP_NAK        10                /* (ATM)ARP NAK.  */

struct arphdr {
        __be16          ar_hrd;         /* format of hardware address   */
        __be16          ar_pro;         /* format of protocol address   */
        unsigned char   ar_hln;         /* length of hardware address   */
        unsigned char   ar_pln;         /* length of protocol address   */
        __be16          ar_op;          /* ARP opcode (command)         */
        unsigned char           ar_sha[ETH_ALEN];       /* sender hardware address      */
        unsigned char           ar_sip[4];                      /* sender IP address            */
        unsigned char           ar_tha[ETH_ALEN];       /* target hardware address      */
        unsigned char           ar_tip[4];                      /* target IP address            */
};


struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};

struct ipv6_lpm_key {
        __u32 prefixlen;
        __u32 data[4];
};

struct ipv4_lpm_map {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __type(key, struct ipv4_lpm_key);
        __type(value, __u8);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __uint(max_entries, MAX_RULES);
} ipv4_lpm_map SEC(".maps");

struct ipv6_lpm_map {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __type(key, struct ipv6_lpm_key);
        __type(value, __u8);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __uint(max_entries, MAX_RULES);
} ipv6_lpm_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 100);
    __type(key, __u32);
    __array(values, struct ipv4_lpm_map);
} outer_hash SEC(".maps") = {
    .values = {(void*)&ipv4_lpm_map},
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 100);
    __type(key, __u32);
    __array(values, struct ipv6_lpm_map);
} outer_hash_v6 SEC(".maps") = {
    .values = {(void*)&ipv6_lpm_map},
};


SEC("xdp")
int xdp_fw_kern_multi_map(struct xdp_md *ctx)
{
    struct ethhdr *ether = NULL;

    void *lpm_map;

    struct iphdr *ipv4 = NULL;
    struct ipv4_lpm_key key4 = { .data=0, .prefixlen=0};

    struct ipv6hdr *ipv6h;
    struct ipv6_lpm_key key6 = { .data=0, .prefixlen=0};

    struct arphdr *arph = NULL;

    __u32 outer_key = 0;
    __u32 outer_key_v6 = 0;

    int ret;

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    ether = data;

    if (data + sizeof(*ether) > data_end) {
        return XDP_ABORTED;
    }

    switch (bpf_ntohs(ether->h_proto)) {

        case ETH_P_ARP:
            arph = (void *)ether + sizeof(*ether);
            if (arph + 1 > data_end)
                return XDP_DROP;

            __builtin_memcpy(&outer_key, ether->h_source + 2, 4);
            lpm_map = bpf_map_lookup_elem(&outer_hash, &outer_key);

            key4.prefixlen = 32;
            memcpy(&key4.data, &arph->ar_sip, 4);

            if (lpm_map) {
                if (key4.data != 0) {
                    __u8 *value = bpf_map_lookup_elem(lpm_map, &key4);
                    __u8 i_index = (__u8)ctx->ingress_ifindex;
                    if (value) {
                        if (*value == i_index) {
                            ret = XDP_PASS;
                            break;
                        }
                    }
                }
                else {
                    ret = XDP_PASS;
                    break;
                }
            }

            ret = XDP_DROP;
            break;

        case ETH_P_IP:
            ipv4 = (void *)ether + sizeof(*ether);
            if (ipv4 + 1 > data_end)
                return XDP_DROP;

            __builtin_memcpy(&outer_key, ether->h_source + 2, 4);
            lpm_map = bpf_map_lookup_elem(&outer_hash, &outer_key);

            if (lpm_map) {
                key4.prefixlen = 32;
                memcpy(&key4.data, &ipv4->saddr, 4);
                __u8 *value = bpf_map_lookup_elem(lpm_map, &key4);
                __u8 i_index = (__u8)ctx->ingress_ifindex;
                if (value) {
                    if (*value == i_index) {
                        ret = XDP_PASS;
                        break;
                    }
                }
            }

            ret = XDP_DROP;
            break;

        case ETH_P_IPV6:

            ipv6h = (void *)ether + sizeof(*ether);
            if ((ipv6h + 1) > data_end)
                return XDP_DROP;

            __builtin_memcpy(&outer_key_v6, ether->h_source + 2, 4);

            lpm_map = bpf_map_lookup_elem(&outer_hash_v6, &outer_key_v6);

            if (lpm_map) {
                key6.prefixlen = 128;
                memcpy(&key6.data, &ipv6h->saddr, 16);
                __u8 *value = bpf_map_lookup_elem(lpm_map, &key6);
                __u8 i_index = (__u8)ctx->ingress_ifindex;

                if (value) {
                    if (*value == i_index) {
                        if (ipv6h->nexthdr == IPPROTO_ICMPV6) {
                            struct icmp6hdr *icmp6h = (data + sizeof(*ether) + sizeof(*ipv6h));
                            if (icmp6h + 1 > (struct icmp6hdr *)data_end) {
                                return XDP_ABORTED;
                            }
                            if (icmp6h->icmp6_type == 136 && icmp6h->icmp6_code == 0) {
                                void *tgt_address = (void *)(data + sizeof(*ether) + sizeof(*ipv6h) + sizeof(*icmp6h));
                                if (tgt_address + 16> data_end)
                                    return XDP_DROP;

                                key6.prefixlen = 128;
                                memcpy(&key6.data, tgt_address, 16);
                                if (bpf_map_lookup_elem(lpm_map, &key6)) {
                                    ret = XDP_PASS;
                                    break;
                                }
                                else {
                                    ret = XDP_DROP;
                                    break;
                                }
                            }
                            else {
                                ret = XDP_PASS;
                                break;
                            }
                        }
                        else {
                            ret = XDP_PASS;
                            break;
                        }
                    }
                }
            }

            ret = XDP_DROP;
            break;
        default:
            ret = XDP_PASS;
            break;
    }

        return ret;
}

char _license[] SEC("license") = "GPL";

