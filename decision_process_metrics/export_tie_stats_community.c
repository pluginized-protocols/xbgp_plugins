//
// Created by thomas on 15/02/22.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_metrics.h"
#include "../prove_stuffs/prove.h"
#include "../prove_stuffs/prove_helpers.h"

/* entry point */
uint64_t export_tie_stats_community(void);

static void __always_inline update_stats(uint64_t *stats, enum bgp_selection_reason reason) {
    int idx;

    switch (reason) {
        case bgp_selection_first:
            idx = TIE_INITIAL_RTE;
            break;
        case bgp_selection_local_pref:
            idx = TIE_LOCAL_PREF;
            break;
        case bgp_selection_as_path:
            idx = TIE_AS_PATH;
            break;
        case bgp_selection_origin:
            idx =  TIE_ORIGIN;
            break;
        case bgp_selection_med:
            idx = TIE_MED;
            break;
        case bgp_selection_igp_metric:
            idx = TIE_IGP_COST;
            break;
        case bgp_selection_tie_breaker:
            idx = TIE_BREAKER;
            break;
        default:
            idx = TIE_OTHER;
            break;
    }

    stats[TIE_TOTAL_ROUTES] += 1;
    stats[idx] += 1;
}

static __always_inline void *get_mem(void) {
    void *stats;
    stats = ctx_shmget(SHM_KEY_TIE_BREAKER_STATS);
    if (!stats) {
        stats = ctx_shmnew(SHM_KEY_TIE_BREAKER_STATS, sizeof(uint64_t) * TIE_MAX);
        if (!stats) {
            return NULL;
        }
    }
    return stats;
}

PROOF_INSTS(
#define NEXT_RETURN_VALUE FAIL
        unsigned int nondet_uint(void);

        struct path_attribute *get_attr_from_code(uint8_t code) {
            struct path_attribute *new_communities = ctx_malloc(sizeof(*new_communities) + sizeof(uint32_t));

            new_communities->code = COMMUNITY_ATTR_ID;
            new_communities->length = sizeof(uint32_t); // only one community will be added
            new_communities->flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;

            return new_communities;
        }
)

#define TIDYING1() \
PROOF_INSTS(do {\
if (attr) ctx_free(attr); \
} while(0))

#define TIDYING2() \
PROOF_INSTS(do {\
if (new_attr) ctx_free(new_attr); \
} while(0))

uint64_t export_tie_stats_community(void) {
    enum TIE_BREAKER tb;
    int idx;
    struct path_attribute *attr, *new_attr;
    uint64_t *stats;
    uint32_t *communities;
    uint64_t total_routes;
    uint16_t proportion;
    unsigned int old_community_len;
    unsigned int new_community_len;
    struct bgp_rte_info *rte_info;

    attr = get_attr_from_code(COMMUNITY_ATTR_ID);
    rte_info = get_route_info();

    if (!rte_info) {
        ebpf_print("Unable to get route info ! SHOULD NOT HAPPEN !\n");
    }

    old_community_len = attr ? attr->length : 0;
    new_community_len = old_community_len + (sizeof(uint32_t) * (TIE_MAX)) + 4; // 4 for rte info reason

    stats = get_mem();
    if (!stats) {
        ebpf_print("wow no stats !\n");
        next();
        TIDYING1();
        return PLUGIN_FILTER_UNKNOWN;
    }

    update_stats(stats, rte_info->reason);

    new_attr = ctx_malloc(new_community_len + sizeof(*attr));
    if (!new_attr) {
        ebpf_print("Unable to allocate memory for COMMUNITY ATTR\n");
        next();
        TIDYING1();
        return PLUGIN_FILTER_UNKNOWN;
    }

    new_attr->code = COMMUNITY_ATTR_ID;
    new_attr->flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;
    new_attr->length = new_community_len;

    if (new_community_len > 255) {
        new_attr->flags |= ATTR_EXT_LEN;
    }

    /* cpy attr */
    if (attr) {
        ebpf_memcpy(new_attr->data, attr->data, old_community_len);
    }

    /* points at the end of the new community list */
    communities = (uint32_t *) (new_attr->data + old_community_len);
    total_routes = stats[TIE_TOTAL_ROUTES];

    idx = 0;
    communities[idx++] = ebpf_htonl(((TIE_BREAKER_COMMUNITY) << 16) | (rte_info->reason & 0xFF));
    for (tb = TIE_INITIAL_RTE; tb < TIE_MAX; tb++) {
        uint64_t tmp1 = stats[tb] > UINT64_MAX/1000 ? UINT64_MAX : stats[tb] * 1000;
        proportion = total_routes == 0 ? 0 : (tmp1/total_routes > UINT16_MAX ? UINT16_MAX : tmp1/total_routes);
        communities[idx++] = ebpf_htonl(((TIE_BREAKER_COMMUNITY + (uint32_t) tb) << 16) | (proportion & 0xFF));
    }

    if (set_attr(new_attr)) {
        ebpf_print("Unable to set_attr COMMUNITY Attribute\n");
    }

    /* this filter doesn't decide anything */
    TIDYING2();
    return PLUGIN_FILTER_UNKNOWN;
}

PROOF_INSTS(
        int main(void) {
            ctx_shmnew(SHM_KEY_TIE_BREAKER_STATS, 8995);
            uint64_t ret_val = export_tie_stats_community();

            p_assert(ret_val == 0 ||
            ret_val == PLUGIN_FILTER_UNKNOWN);

            ctx_shmrm(SHM_KEY_TIE_BREAKER_STATS);

            return 0;
        }
        )