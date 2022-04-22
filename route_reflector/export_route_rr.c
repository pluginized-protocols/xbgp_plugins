//
// Created by thomas on 19/05/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_rr.h"
#include "../prove_stuffs/prove.h"

/* starting point */
uint64_t export_route_rr(args_t *args UNUSED);

PROOF_INSTS(
        struct ubpf_peer_info *nondet_get_pinfo__verif(void);
        uint16_t nondet_get_u16__verif(void);

        static uint16_t data_length = 0;

        struct ubpf_peer_info *get_peer_info(int *nb_peers) {
            struct ubpf_peer_info *pinfo;

            pinfo = malloc(sizeof(*pinfo) * 2);
            if (!pinfo) return NULL;

            PROOF_CBMC_INSTS(__CPROVER_havoc_object(pinfo));

            pinfo->peer_type = IBGP_SESSION;
            pinfo->local_bgp_session = &pinfo[1];
            return pinfo;
        }

        struct ubpf_peer_info *get_src_peer_info() {
            int i = 1;
            return get_peer_info(&i);
        }

        struct path_attribute *get_attr_from_code(uint8_t code) {
            struct path_attribute *p_attr;

            switch (code) {
                case ORIGINATOR_ID_ATTR_ID:
                case CLUSTER_LIST:
                    if (data_length == 0) {
                        data_length = nondet_get_u16__verif();
                        p_assume(data_length % 4 == 0);
                    }
                    uint16_t final_length = code == ORIGINATOR_ID ? 4 : data_length;

                    p_attr = malloc(sizeof(*p_attr) + final_length);
                    if (!p_attr) return NULL;

                    p_attr->code = code;
                    p_attr->flags = ATTR_OPTIONAL;
                    p_attr->length = final_length;
                    return p_attr;
                default:
                    //p_assert(0);
                    return NULL;
            }
            return NULL;
        }

#define NEXT_RETURN_VALUE PLUGIN_FILTER_UNKNOWN
)

#define TIDYING() \
PROOF_INSTS(do { \
    if (pinfo) free(pinfo);        \
    if (src_info) free(src_info);        \
    if (originator) free(originator);        \
    if (cluster_list) free(cluster_list);        \
}while(0))


uint64_t export_route_rr(args_t *args UNUSED) {
    unsigned int i;
    int must_set_originator = 0;
    int nb_peers;
    uint32_t *cluster_array;
    unsigned int cl_length;
    char *cl_array;

    struct path_attribute *originator = NULL;
    struct path_attribute *cluster_list = NULL;
    struct path_attribute *new_cluster_list = NULL;

    struct ubpf_peer_info *pinfo = get_peer_info(&nb_peers);
    struct ubpf_peer_info *src_info = get_src_peer_info();


    if (!pinfo || !src_info) {
        ebpf_print("Unable to get peer info\n");
        TIDYING();
        next();
    }

    if (pinfo->peer_type != IBGP_SESSION || src_info->peer_type != IBGP_SESSION) {
        // we do not reflect to other iBGP sessions
        // ebpf_print("Not iBGP between the two peers\n");
        TIDYING();
        next();
    }

    // Update group disallows this functionality
    //if (pinfo->router_id == src_info->router_id) {
    //    // don't send back to the sender
    //    return PLUGIN_FILTER_REJECT;
    //}

    originator = get_attr_from_code(ORIGINATOR_ID);
    cluster_list = get_attr_from_code(CLUSTER_LIST);

    if (originator) {
        if (*(uint32_t *) originator->data != src_info->router_id) {
            ebpf_print("Originator ID is the SAME, update rejected\n");
            TIDYING();
            return PLUGIN_FILTER_REJECT;
        }
    }

    if (cluster_list) {
        if (cluster_list->length > UINT16_MAX - 4) {
            TIDYING();
            return PLUGIN_FILTER_UNKNOWN;
        }
    }

    if (cluster_list != NULL) {
        if (cluster_list->length > 0) {

            if (cluster_list->length > 255) {
                TIDYING();
                return PLUGIN_FILTER_REJECT;
            }

            /* check if our cluster-id/router-id is in the received cluster list */
            cluster_array = (uint32_t *) cluster_list->data;
            for (i = 0; i < cluster_list->length / 4; i++) {
                if (cluster_array[i] == pinfo->local_bgp_session->router_id) {
                    ebpf_print("My router-id %d is in the cluster list (rcv %d)!\n",
                               LOG_U32(pinfo->local_bgp_session->router_id), LOG_U32(src_info->router_id));
                    TIDYING();
                    return PLUGIN_FILTER_UNKNOWN;
                }
            }
        }
    }

    /* check according to client-non client sessions */
    if (!is_rr_client(src_info->router_id)) {
        /* route coming from a non client, send to clients only */
        if (!is_rr_client(pinfo->router_id)) { // only check the first peer of the subgroup
            /* the neighbor is not rr client, don't send the route */
            ebpf_print("Reject: received from (%d) not rr client and to non rr client (%d)\n",
                       LOG_U32(src_info->router_id),
                       LOG_U32(pinfo->router_id));
            TIDYING();
            return PLUGIN_FILTER_REJECT;
        }
    }

    /* rr check is done ! */
    /* we now need to change the 2 RR attributes */

    /* add originator id */
    if (!originator) {
        must_set_originator = 1;
        originator = ctx_malloc(sizeof(struct path_attribute) + sizeof(uint32_t));
        if (!originator) {
            // fail !!!
            ebpf_print("Unable to allocate memory for ORIGINATOR_ID\n");
            TIDYING();
            return PLUGIN_FILTER_REJECT;
        }
        originator->code = ORIGINATOR_ID;
        originator->flags = ATTR_OPTIONAL; // originator is non transitive !
        originator->length = 4;
        *((uint32_t *) originator->data) = src_info->router_id;
    }

    /* prepend our router id/cluster id in cluster list */
    cl_length = 4;
    if (cluster_list) {
        cl_length += cluster_list->length;
    }

    new_cluster_list = ctx_malloc(sizeof(*new_cluster_list) + cl_length);
    if (!new_cluster_list) {
        ebpf_print("Unable to allocate space for cluster list\n");
        return PLUGIN_FILTER_UNKNOWN;
    }
    new_cluster_list->code = CLUSTER_LIST_ATTR_ID;
    new_cluster_list->flags = ATTR_OPTIONAL;
    new_cluster_list->length = cl_length;
    cl_array = (char *) new_cluster_list->data;

    /* prepend our cluster list */
    memcpy(cl_array, &src_info->local_bgp_session->router_id, 4);
    if (cluster_list) {
        /* copy the rest of the cluster list */
        ebpf_memcpy(cl_array + 4, cluster_list->data, cluster_list->length);
    }

    if (set_attr(new_cluster_list) != 0) {
        ebpf_print("Unable to set cluster list attr !\n");
    }

    if (must_set_originator) {
        if (set_attr(originator) != 0) {
            ebpf_print("Unable to set orignator id attr!\n");
        }
    }

    TIDYING();
    next();
    return PLUGIN_FILTER_ACCEPT;
}


PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t rt_val = export_route_rr(&args);

            PROOF_SEAHORN_INSTS(
                    RET_VAL_FILTERS_CHECK(rt_val);
            )
            return 0;
        }
)