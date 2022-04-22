//
// Created by thomas on 15/02/22.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_metrics.h"
#include "../prove_stuffs/prove.h"
#include "../prove_stuffs/prove_helpers.h"

uint64_t tie_breaker(exec_info_t *info);

PROOF_INSTS(
#define NEXT_RETURN_VALUE EXIT_SUCCESS
)

uint64_t tie_breaker(exec_info_t *info) {
    uint64_t *stats;
    unsigned int tie_reason, old_comm_len, new_comm_len;
    struct path_attribute *communities, *new_communities;
    int rte;

    stats = ctx_shmget(SHM_KEY_TIE_BREAKER_STATS);
    if (!stats) {
        stats = ctx_shmnew(SHM_KEY_TIE_BREAKER_STATS, sizeof(uint64_t) * TIE_MAX);
        if (!stats) {
            return BPF_FAILURE;
        }
    }

    /*
     * if the return value is not set
     * then skip this plugin
     */
    if (!info->return_val_set) {
        return BPF_CONTINUE;
    }

    switch (info->insertion_point_id) {
        case BGP_INITIAL_RTE_DECISION:
            tie_reason = TIE_INITIAL_RTE;
            break;
        case BGP_PRE_DECISION:
            tie_reason = TIE_OTHER;
            break;
        case BGP_LOCAL_PREF_DECISION:
            tie_reason = TIE_LOCAL_PREF;
            break;
        case BGP_AS_PATH_LENGTH_DECISION:
            tie_reason = TIE_AS_PATH;
            break;
        case BGP_MED_DECISION:
            tie_reason = TIE_MED;
            break;
        case BGP_USE_ORIGIN_DECISION:
            tie_reason = TIE_ORIGIN;
            break;
        case BGP_PREFER_EXTERNAL_PEER_DECISION:
            tie_reason = TIE_PREFER_EXTERNAL;
            break;
        case BGP_IGP_COST_DECISION:
            tie_reason = TIE_IGP_COST;
            break;
        case BGP_ROUTER_ID_DECISION:
            tie_reason = TIE_ROUTER_ID;
            break;
        case BGP_IPADDR_DECISION:
            tie_reason = TIE_OTHER;
            break;
        case BGP_POST_DECISION:
            tie_reason = TIE_OTHER;
            break;
        default:
            tie_reason = TIE_DEFAULT;
            break;
    }

    if (tie_reason < 0) {
        return BPF_FAILURE;
    }

    stats[TIE_TOTAL_ROUTES] += 1;
    stats[tie_reason] += 1;

    rte = info->replace_return_value == BGP_ROUTE_TYPE_NEW ? BGP_ROUTE_TYPE_NEW :
          info->replace_return_value == BGP_ROUTE_TYPE_OLD ? BGP_ROUTE_TYPE_OLD : -1;

    if (rte == -1) {
        ebpf_print("HOST IMPLEM BUG !\n");
        return BPF_FAILURE;
    }

    communities = get_attr_from_code_by_route(COMMUNITY_ATTR_ID, rte);

    old_comm_len = 0;
    if (communities) {
        old_comm_len = communities->length;
    }
    new_comm_len = old_comm_len + sizeof(uint32_t);

    new_communities = ctx_malloc(sizeof(*new_communities) + new_comm_len);
    if (!new_communities) {
        return BPF_FAILURE;
    }

    /* TODO enhance this: recreate again the communities... */
    new_communities->code = COMMUNITY_ATTR_ID;
    new_communities->length = new_comm_len; // only one community will be added
    new_communities->flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;
    if (new_comm_len > 255) {
        new_communities->flags |= ATTR_EXT_LEN;
    }

    /* recopy communities to the new one */
    if (communities) {
        ebpf_memcpy(new_communities->data, communities->data, communities->length);
    }

    /* add the tie breaker ! */
    *((uint32_t *) (&new_communities->data[old_comm_len])) =
            ebpf_htonl((TIE_BREAKER_COMMUNITY << 16) | (tie_reason & 0xffu));

    /* must add the attribute to the route that has
     * been selected by the host implementation */
    if (set_attr_to_route(new_communities, rte) != 0) {
        ebpf_print("Unable to set attr!\n");
        return BPF_FAILURE;
    }

    return BPF_SUCCESS;
}

PROOF_INSTS(
        int main(void) {

            exec_info_t info = {};
            uint64_t ret_val = tie_breaker(&info);

            p_assert(ret_val == BPF_CONTINUE ||
                     ret_val == BPF_SUCCESS ||
                     ret_val == BPF_FAILURE);

            ctx_shmrm(SHM_KEY_TIE_BREAKER_STATS);

            return 0;
        }
)