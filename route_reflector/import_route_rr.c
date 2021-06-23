//
// Created by thomas on 19/05/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include <bytecode_public.h>
#include "common_rr.h"
#include "../prove_stuffs/prove.h"


#ifdef PROVERS
struct ubpf_peer_info *nondet_get_pinfo__verif();
uint16_t nondet_get_u16__verif();

struct ubpf_peer_info *get_peer_info(int *nb_peers) {
    struct ubpf_peer_info *pinfo = nondet_get_pinfo__verif();
    pinfo->peer_type = IBGP_SESSION;
    return pinfo;
}

struct ubpf_peer_info *get_src_peer_info() {
    struct ubpf_peer_info *pinfo = nondet_get_pinfo__verif();
    pinfo->peer_type = IBGP_SESSION;
    return pinfo;
}

struct path_attribute *get_attr_from_code(uint8_t code) {
    struct path_attribute *p_attr;
    p_attr = malloc(sizeof(*p_attr));

    switch (code) {
        case ORIGINATOR_ID:
        case CLUSTER_LIST:
            p_attr->code = code;
            p_attr->flags = ATTR_TRANSITIVE | ATTR_OPTIONAL;
            p_attr->length = code == ORIGINATOR_ID ? 4 : nondet_get_u16__verif();
            break;
        default:
            p_assert(0);
            return NULL;
    }
    return NULL;
}

#include "../prove_stuffs/mod_ubpf_api.c"
#define next() return PLUGIN_FILTER_UNKNOWN
#endif

uint64_t import_route_rr(args_t *args UNUSED) {

    int i;
    struct path_attribute *originator;
    struct path_attribute *cluster_list;
    struct ubpf_peer_info *pinfo;

    uint32_t originator_id;
    uint32_t router_id;

    uint32_t *cluster_array;

    // int true = 1;

    originator = get_attr_from_code(ORIGINATOR_ID);
    cluster_list = get_attr_from_code(CLUSTER_LIST);
    pinfo = get_src_peer_info();

    if (!pinfo) {
        ebpf_print("I don't have the required arguments to import with RR enabled");
        return PLUGIN_FILTER_REJECT;
    }

    router_id = pinfo->local_bgp_session->router_id;
    if (pinfo->peer_type == EBGP_SESSION) next();
    if (!originator || !cluster_list) next(); /// XXX: check this

    originator_id = *(uint32_t *) originator->data;

    /* 1. Check router ID */
    if (originator_id == router_id) {
        return PLUGIN_FILTER_REJECT;
    }

    /* 2. Is Router ID contained in the CLUSTER_LIST ? */
    cluster_array = (uint32_t *) cluster_list->data;
    for (i = 0; i < cluster_list->length / 4; i++) {
        if (cluster_array[i] == router_id) {
            return PLUGIN_FILTER_REJECT;
        }
    }

    next(); // next filter to import
    return PLUGIN_FILTER_ACCEPT;
}

#ifdef PROVERS
int main(void) {
    args_t args = {};
    uint64_t rt_val = import_route_rr(&args);
#ifdef PROVERS_SH
    RET_VAL_FILTERS_CHECK(rt_val);
#endif
    return 0;
}
#endif