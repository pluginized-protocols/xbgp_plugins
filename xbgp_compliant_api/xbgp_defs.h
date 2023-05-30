//
// Created by thomas on 20/11/20.
//

#ifndef PLUGINIZED_FRR_XBGP_DEFS_H
#define PLUGINIZED_FRR_XBGP_DEFS_H

#include <time.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "xbgp_common.h"
//#include "tools_ubpf_api.h"

#define UNUSED __attribute__((unused))

#define FAIL 0

/* REGISTERED ATTRIBUTE ID */

#define RESERVED_ATTR_ID 0
#define ORIGIN_ATTR_ID 1
#define AS_PATH_ATTR_ID 2
#define NEXT_HOP_ATTR_ID 3
#define MULTI_EXIT_DISC_ATTR_ID 4
#define LOCAL_PREF_ATTR_ID 5
#define ATOMIC_AGGREGATE_ATTR_ID 6
#define AGGREGATOR_ATTR_ID 7
#define COMMUNITY_ATTR_ID 8
#define ORIGINATOR_ID_ATTR_ID 9
#define CLUSTER_LIST_ATTR_ID 10
#define MP_REACH_NLRI_ATTR_ID 14
#define MP_UNREACH_NLRI_ATTR_ID 15
#define EXTENDED_COMMUNITIES_ATTR_ID 16
#define AS4_PATH_ATTR_ID 17
#define AS4_AGGREGATOR_ATTR_ID 18
#define PMSI_TUNNEL_ATTR_ID 22
#define TUNNEL_ENCAPSULATION_ATTRIBUTE_ATTR_ID 23
#define TRAFFIC_ENGINEERING_ATTR_ID 24
#define IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITY_ATTR_ID 25
#define AIGP_ATTR_ID 26
#define PE_DISTINGUISHER_LABELS_ATTR_ID 27
#define BGPLS_ATTRIBUTE_ATTR_ID 29
#define LARGE_COMMUNITY_ATTR_ID 32
#define BGPSEC_PATH_ATTR_ID 33
#define BGP_COMMUNITY_CONTAINER_ATTRIBUTE_TEMPORARY_REGISTERED_20170728_ATTR_ID 34
#define ONLY_TO_CUSTOMER_OTC_TEMPORARY_REGISTERED_20180329_ATTR_ID 35
#define BGP_DOMAIN_PATH_DPATH_TEMPORARY_REGISTERED_20190708_ATTR_ID 36
#define SFP_ATTRIBUTE_ATTR_ID 37
#define BGP_PREFIXSID_ATTR_ID 40
#define ATTR_SET_ATTR_ID 128

/* ATTRIBUTE FLAGS */
#define ATTR_OPTIONAL		0x80
#define ATTR_TRANSITIVE		0x40
#define ATTR_PARTIAL		0x20
#define ATTR_EXT_LEN		0x10

/* AS_PATH_SEGMENT_TYPE */
#define AS_PATH_SEGMENT_SET             1
#define AS_PATH_SEGMENT_SEQUENCE        2
#define AS_PATH_SEGMENT_CONFED_SEQUENCE 3
#define AS_PATH_SEGMENT_CONFED_SET      4

/* ORIGIN */
#define BGP_ORIGIN_IGP                           0
#define BGP_ORIGIN_EGP                           1
#define BGP_ORIGIN_INCOMPLETE                    2

#define iana_afi_to_af(afi) ({ \
    int __af_type;                      \
    switch(afi) {         \
        case XBGP_AFI_IPV4: \
            __af_type = AF_INET;        \
            break;        \
        case XBGP_AFI_IPV6:             \
            __af_type = AF_INET6;       \
            break;        \
        default:          \
            __af_type = -1;             \
            break;        \
    }                     \
    __af_type;\
})

enum ubpf_plugins {
    BGP_UNUSED = 0,
    BGP_PRE_DECISION,
    BGP_NEXTHOP_RESOLVABLE_DECISION,
    BGP_LOCAL_PREF_DECISION,
    BGP_AS_PATH_LENGTH_DECISION,
    BGP_MED_DECISION, // decision process MED insertion point
    BGP_USE_ORIGIN_DECISION,
    BGP_PREFER_EXTERNAL_PEER_DECISION,
    BGP_IGP_COST_DECISION,
    BGP_ROUTER_ID_DECISION,
    BGP_IPADDR_DECISION,
    BGP_POST_DECISION,
    BGP_DECODE_ATTR,
    BGP_ENCODE_ATTR,
    BGP_ENCODE_CUSTOM_ATTR,
    BGP_PRE_INBOUND_FILTER,
    BGP_PRE_OUTBOUND_FILTER,
    BGP_DECODE_MESSAGE,
    BGP_ENCODE_MESSAGE,
    BGP_OPEN_SENT,
    BGP_INITIAL_RTE_DECISION,

    INSERTION_POINT_RESERVED = 2000000000
};

enum ubpf_arg_type {
    ARG_UNUSED = 0,
    ARG_CODE,
    ARG_TYPE,
    ARG_LENGTH,
    ARG_FLAGS,
    ARG_DATA,
    ARG_BGP_ROUTE,
    ARG_BGP_ROUTE_NEW,
    ARG_BGP_ROUTE_OLD,
    ARG_BGP_ROUTE_RIB,
    ARG_BGP_ATTRIBUTE_LIST,
    ARG_BGP_ATTRIBUTE,
    ARG_BUFFER,
    ARG_BGP_PREFIX,
    ARG_BGP_VRF,
    ARG_BGP_MESSAGE,


    ARG_MAX_OPAQUE // can be used to init the personal enum
};

enum {
    EBGP_SESSION,
    IBGP_SESSION,
    LOCAL_SESSION,
};

enum BGP_ROUTE_TYPE {
    BGP_ROUTE_TYPE_UNDEF = HI_RESERVED_RETURN_VAL + 1,
    BGP_ROUTE_TYPE_NEW,
    BGP_ROUTE_TYPE_OLD,
    BGP_ROUTE_TYPE_UNKNOWN,
    BGP_ROUTE_TYPE_FAIL
};

enum BGP_PLUGIN_FILTER_DECISION {
    PLUGIN_FILTER_REJECT = HI_RESERVED_RETURN_VAL + 1,
    PLUGIN_FILTER_ACCEPT,
    PLUGIN_FILTER_UNKNOWN,
};


enum bgp_selection_reason {
    bgp_selection_none,
    bgp_selection_first,
    bgp_selection_local_pref,
    bgp_selection_local_route,
    bgp_selection_as_path,
    bgp_selection_origin,
    bgp_selection_med,
    bgp_selection_peer,
    bgp_selection_igp_metric,
    bgp_selection_older,
    bgp_selection_tie_breaker,
    bgp_selection_cluster_length,
    bgp_selection_local_configured,
    bgp_selection_other,
    bgp_selection_default,
};

struct bgp_message {
    int type;
    size_t buf_len;
    uint8_t *buf;
};

struct path_attribute {
    uint8_t code;
    uint8_t flags;
    unsigned int length;
    uint8_t data[0];
};

struct ubpf_peer_info {
    uint32_t as;
    uint32_t router_id;
    uint32_t capability;
    uint8_t peer_type; // iBGP, eBGP, or LOCAL for local_bgp_sessions field.

    struct {
        uint8_t type;
        union {
            struct in6_addr in6;
            struct in_addr in;
        };
    } nexthop;

    // uint32_t nexthop;

    struct {
        uint8_t af;
        union {
            struct in6_addr in6;
            struct in_addr in;
        } addr;
    } addr;

    struct ubpf_peer_info *local_bgp_session; // NULL if the structure is about the local BGP router.
};

enum xbgp_afi {
    XBGP_AFI_IPV4 = 1,
    XBGP_AFI_IPV6 = 2
};

enum xbgp_safi {
    XBGP_SAFI_UNICAST = 1,
};

struct ubpf_prefix {
    uint16_t afi;
    uint8_t safi;
    uint8_t padding;
    uint16_t prefixlen;
    uint8_t u[20];
};

struct bgp_rte_info {
    time_t uptime;
    uint32_t type;  // CONNECTED, STATIC, IGP, BGP
    enum bgp_selection_reason reason;
};

struct bgp_route {
    struct ubpf_prefix pfx;
    int attr_nb;
    struct path_attribute **attr;
    struct ubpf_peer_info *peer_info;
    struct bgp_rte_info route_info;
};

struct ubpf_nexthop {
    uint8_t route_type; // connected, static, kernel
    uint64_t igp_metric;
};

struct vrf_info {
    int vrf_id;
    size_t str_len;
    char name[0];
};


/*
 * memset and memcpy are
 * only for static arrays !!! i.e. whose sizes
 * are known at compile time !
 *
 * clang compiler will transform those calls
 * to their corresponding asm instructions
 *
 * If the memory area length is not known at compile
 * time (i.e. dynamic array) then use the
 * corresponding ebpf_<fun> alternative API call
 */
void *memset(void *s, int c, size_t n);

void *memcpy(void *dest, const void *src, size_t len);


#endif //PLUGINIZED_FRR_XBGP_DEFS_H
