//
// Created by thomas on 19/05/20.
//

#include "../../public_bpf.h"
#include "ubpf_api.h"
#include "common_rr.h"

uint64_t import_route_rr(bpf_full_args_t *args UNUSED) {

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
    for (i = 0; i < cluster_list->len / 4; i++) {
        if (cluster_array[i] == router_id) {
            return PLUGIN_FILTER_REJECT;
        }
    }

    next(); // next filter to import
    return PLUGIN_FILTER_ACCEPT;
}