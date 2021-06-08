//
// Created by thomas on 19/05/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include <bytecode_public.h>
#include "common_rr.h"
#include "../prove_stuffs/prove.h"


#ifdef PROVERS

struct ubpf_peer_info *get_pinfo();
uint16_t get_u16();

struct ubpf_peer_info *get_peer_info(int *nb_peers) {
    struct ubpf_peer_info *pinfo = get_pinfo();
    pinfo->peer_type = IBGP_SESSION;
    return pinfo;
}

struct ubpf_peer_info *get_src_peer_info() {
    struct ubpf_peer_info *pinfo = get_pinfo();
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
            p_attr->length = code == ORIGINATOR_ID ? 4 : get_u16();
            break
        default:
            p_assert(0);
            return NULL;
    }
    return
}
#endif

#ifdef PROVERS_SH
#include "../prove_stuffs/mod_ubpf_api.c"
#endif

uint64_t export_route_rr(args_t *args UNUSED) {

    int i, nb_peers, cl_len;
    uint32_t *cluster_array;

    struct path_attribute *originator;
    struct path_attribute *cluster_list;

    struct path_attribute *new_cluster_list;

    struct ubpf_peer_info *pinfo = get_peer_info(&nb_peers);
    struct ubpf_peer_info *src_info = get_src_peer_info();

    if (!pinfo || !src_info) {
        ebpf_print("Unable to get peer info\n");
        next();
    }

    if (pinfo->peer_type != IBGP_SESSION || src_info->peer_type != IBGP_SESSION) {
        // we do not reflect to other iBGP sessions
        next();
    }

    // Update group disallows this functionality
    //if (pinfo->router_id == src_info->router_id) {
    //    // don't send back to the sender
    //    return PLUGIN_FILTER_REJECT;
    //}

    originator = get_attr_from_code(ORIGINATOR_ID);
    cluster_list = get_attr_from_code(CLUSTER_LIST);

    cl_len = 4 + (cluster_list ? cluster_list->length : 0);

    new_cluster_list = ctx_malloc(sizeof(struct path_attribute) + cl_len);
    if (!new_cluster_list) {
        ebpf_print("Unable to get memory for cluster list (%d + %d)\n", sizeof(struct path_attribute), cl_len);
        return FAIL;
    }
    new_cluster_list->code = CLUSTER_LIST_ATTR_ID;
    new_cluster_list->flags = 0x80;
    new_cluster_list->length = cl_len;

    //ebpf_print("memory for cluster list (%d + %d)\n", sizeof(struct path_attribute), cl_len);

    if (cluster_list != NULL) {
        if (cluster_list->length > 0) {

            if (cluster_list->length > 255) return PLUGIN_FILTER_REJECT;

            /* check if our cluster-id/router-id is in the received cluster list */
            cluster_array = (uint32_t *) cluster_list->data;
            for (i = 0; i < cluster_list->length / 4; i++) {
                if (cluster_array[i] == pinfo->local_bgp_session->router_id) {
                    ebpf_print("My router-id %d is in the cluster list (rcv %d)!\n",
                               pinfo->local_bgp_session->router_id, src_info->router_id);
                    return PLUGIN_FILTER_REJECT;
                }
            }
        }
    }

    /* check according to client-non client sessions */
    if (!is_rr_client(src_info->router_id)) {
        /* route coming from a non client, send to clients only */
        if (!is_rr_client(pinfo->router_id)){ // only check the first peer of the subgroup
            /* the neighbor is not rr client, don't send the route*/
            ebpf_print("Reject: received from (%d) not rr client and to non rr client (%d)\n", src_info->router_id, pinfo->router_id);
            return PLUGIN_FILTER_REJECT;
        }
    }

    if (!originator) {
        // must set the ORIGINATOR ID
        originator = ctx_malloc(sizeof(struct path_attribute) + sizeof(uint32_t));
        if (!originator) {
            // fail !!!
            ebpf_print("Unable to allocate memory for ORIGINATOR_ID\n");
            return FAIL;
        }
        originator->code = ORIGINATOR_ID;
        originator->flags = 0x80; // originator is non transitive !
        originator->length = 4;
        *((uint32_t *)originator->data) = src_info->router_id;

    }


    /* prepend our router_id */
    ((uint32_t *)new_cluster_list->data)[0] = src_info->local_bgp_session->router_id; //pinfo->local_bgp_session->router_id;

    if (cluster_list != NULL) {
        if (cluster_list->length != 0) {
            ebpf_memcpy(new_cluster_list + 4, cluster_list->data, cluster_list->length);
        }
    }

    set_attr(originator);
    set_attr(new_cluster_list);
    next();
    return PLUGIN_FILTER_ACCEPT;
}

#ifdef PROVERS_SH
int main(void) {
    args_t args = {};
    uint64_t rt_val = export_route_rr(&args);

    RET_VAL_FILTERS_CHECK(rt_val);
    return 0;
}
#endif