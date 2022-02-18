//
// Created by thomas on 15/02/22.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_metrics.h"

/* entry point */
uint64_t export_tie_stats_community(void);

uint64_t export_tie_stats_community(void) {
    enum TIE_BREAKER tb;
    int idx = 0;
    struct path_attribute *attr, *realloc_attr;
    uint64_t *stats;
    uint32_t *communities;
    unsigned int new_community_len;

    attr = get_attr_from_code(COMMUNITY_ATTR_ID);
    if (!attr) {
        next();
        return 0;
    }

    new_community_len = attr->length + (sizeof(uint32_t) * (TIE_MAX - 1));

    stats = ctx_shmget(SHM_KEY_TIE_BREAKER_STATS);
    if (!stats) {
        next();
        return PLUGIN_FILTER_UNKNOWN;
    }

    realloc_attr = ctx_realloc(attr, new_community_len + sizeof(*attr));
    if (!realloc_attr) {
        ebpf_print("Unable to allocate memory for COMMUNITY ATTR\n");
        next();
        return PLUGIN_FILTER_UNKNOWN;
    }

    /* points at the end of the new community list */
    communities = (uint32_t *) (realloc_attr->data + attr->length);

    for (tb = TIE_LOCAL_PREF; tb < TIE_MAX; tb++) {
        uint16_t counter = stats[tb];
        communities[idx++] = ebpf_htonl(((TIE_BREAKER_COMMUNITY + tb) < 2) | (counter));
    }

    if (set_attr(realloc_attr)) {
        ebpf_print("Unable to set_attr COMMUNITY Attribute\n");
    }

    /* this filter doesn't decide anything */
    return PLUGIN_FILTER_UNKNOWN;
}