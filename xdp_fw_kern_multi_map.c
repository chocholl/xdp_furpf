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

#define FRAME_SIZE        1000000000

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

typedef struct bucket {
    __u64 start_time;
    __u64 headroom;
    __u64 last_packet_time;
    __u32 transmitted;
} t_bucket;

struct  {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 100);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} cir SEC(".maps");

struct  {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, t_bucket);
    __uint(max_entries, 100);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} state_map SEC(".maps");

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

static __always_inline __u32 rate_limit(__u32 *key, __u32 frame_len) {
    __u32 thr;
    __u32 *thr_value;

    thr_value = bpf_map_lookup_elem(&cir, key);

    if (!thr_value) {
        return XDP_PASS;
    } else {
        thr = *thr_value;
    }

    if (thr == 0) {
        return XDP_PASS;
    }

    t_bucket *b = bpf_map_lookup_elem(&state_map, key);
    __u64 now = bpf_ktime_get_ns();
    if (b)
    {
        __u64 elapsed = now - b->start_time;
        if (elapsed >= FRAME_SIZE) {
            b->start_time = now;
            b->last_packet_time = now;
            b->headroom = thr - frame_len;
            b->transmitted = frame_len;
            return XDP_PASS;
        }
        else {
            __u64 inter_packet_gap = now - b->last_packet_time;
            __u64 burst = (thr * inter_packet_gap) / (FRAME_SIZE);
            b->headroom = b->headroom + burst;
            if (b->headroom > thr) {
                b->headroom = thr;
            }
            b->last_packet_time = now;
        }

        if (b->headroom > frame_len) {
            int rnd = now % 100;
            __u64 percent = (100 * thr) / (b->transmitted + 1);

            if (rnd > percent) {
                return XDP_DROP;
            }
            else {
                b->headroom = b->headroom - frame_len;
                b->transmitted = b->transmitted + frame_len;
                return XDP_PASS;
            }
        }
        else {
            return XDP_DROP;
        }
    }
    else {
        struct bucket new_bucket;
        new_bucket.start_time = now;
        new_bucket.last_packet_time = now;
        new_bucket.headroom = thr;
        new_bucket.transmitted = 0;
        bpf_map_update_elem(&state_map, key, &new_bucket, BPF_ANY);
        return XDP_PASS;
    }

    return XDP_DROP;
}

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
    __u32 frame_len = ctx->data_end - ctx->data;

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
                            ret = rate_limit(&outer_key, frame_len);
                            break;
                        }
                    }
                }
                else {
                    ret = rate_limit(&outer_key, frame_len);
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
                        ret = rate_limit(&outer_key, frame_len);
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
                                    ret = rate_limit(&outer_key_v6, frame_len);
                                    break;
                                }
                                else {
                                    ret = XDP_DROP;
                                    break;
                                }
                            }
                            else {
                                ret = rate_limit(&outer_key_v6, frame_len);
                                break;
                            }
                        }
                        else {
                            ret = rate_limit(&outer_key_v6, frame_len);
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
