//
// Created by thomas on 19/05/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_rr.h"
#include "../prove_stuffs/prove.h"


/* starting point */
uint64_t import_route_rr(args_t *args UNUSED);

PROOF_INSTS(
        struct ubpf_peer_info *nondet_get_pinfo__verif();
        uint16_t nondet_get_u16__verif();
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
PROOF_INSTS(do {                       \
    if (pinfo) free(pinfo);                              \
    if (originator) free(originator);                    \
    if (cluster_list) free(cluster_list);                \
} while(0))

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
        TIDYING();
        return PLUGIN_FILTER_REJECT;
    }

    router_id = pinfo->local_bgp_session->router_id;
    if (pinfo->peer_type == EBGP_SESSION) {
        TIDYING();
        next();
    }
    if (!originator || !cluster_list) {
        TIDYING();
        next(); /// XXX: check this
    }

    originator_id = *(uint32_t *) originator->data;

    /* 1. Check router ID */
    if (originator_id == router_id) {
        TIDYING();
        return PLUGIN_FILTER_REJECT;
    }

    /* 2. Is Router ID contained in the CLUSTER_LIST ? */
    cluster_array = (uint32_t *) cluster_list->data;
    for (i = 0; i < cluster_list->length / 4; i++) {
        if (cluster_array[i] == router_id) {
            TIDYING();
            return PLUGIN_FILTER_REJECT;
        }
    }

    TIDYING();
    next(); // next filter to import
    return PLUGIN_FILTER_ACCEPT;
}


PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t rt_val = import_route_rr(&args);

            PROOF_SEAHORN_INSTS(
                    RET_VAL_FILTERS_CHECK(rt_val);
            )
            return 0;
        }
)