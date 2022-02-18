//
// Created by thomas on 15/02/22.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_metrics.h"

uint64_t tie_breaker(exec_info_t *info);

uint64_t tie_breaker(exec_info_t *info) {
    uint64_t *stats;
    int tie_reason, old_comm_len;
    struct path_attribute *communities, *new_communities;

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
        next();
        return BPF_FAILURE;
    }

    switch (info->insertion_point_id) {
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
            tie_reason = TIE_IPADDR;
            break;
        case BGP_POST_DECISION:
            tie_reason = TIE_OTHER;
            break;
        default:
            tie_reason = -1;
            break;
    }

    if (tie_reason < 0) {
        return BPF_FAILURE;
    }

    stats[tie_reason] += 1;

    communities = get_attr_from_code(COMMUNITY_ATTR_ID);

    old_comm_len = 0;
    if (communities) {
        old_comm_len = communities->length;
    }

    new_communities = ctx_malloc(sizeof(*new_communities) + old_comm_len + sizeof(uint32_t));
    if (!new_communities) {
        return BPF_FAILURE;
    }

    /* TODO enhance this: recreate again the communities... */
    new_communities->code = COMMUNITY_ATTR_ID;
    new_communities->length = old_comm_len + sizeof(uint32_t); // only one community will be added
    new_communities->flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;

    if (communities) {
        ebpf_memcpy(new_communities->data, communities->data, communities->length);
    }

    *((uint32_t *) (&new_communities->data[old_comm_len])) =
            ebpf_htonl((TIE_BREAKER_COMMUNITY < 2) | tie_reason);

    if (!set_attr(new_communities)) {
        return BPF_FAILURE;
    }

    return BPF_FAILURE;
}