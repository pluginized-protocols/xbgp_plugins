//
// Created by thomas on 15/02/22.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_metrics.h"
#include "../prove_stuffs/prove.h"
#include "../prove_stuffs/prove_helpers.h"

/* entry point */
uint64_t export_tie_stats_community(void);

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
if (realloc_attr) ctx_free(realloc_attr); \
} while(0))

uint64_t export_tie_stats_community(void) {
    enum TIE_BREAKER tb;
    int idx = 0;
    struct path_attribute *attr, *realloc_attr;
    uint64_t *stats;
    uint32_t *communities;
    int old_length;
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
        TIDYING1();
        return PLUGIN_FILTER_UNKNOWN;
    }

    old_length = attr->length;

    realloc_attr = ctx_realloc(attr, new_community_len + sizeof(*attr));
    if (!realloc_attr) {
        ebpf_print("Unable to allocate memory for COMMUNITY ATTR\n");
        next();
        TIDYING1();
        return PLUGIN_FILTER_UNKNOWN;
    }

    /* points at the end of the new community list */
    communities = (uint32_t *) (realloc_attr->data + old_length);

    for (tb = TIE_LOCAL_PREF; tb < TIE_MAX; tb++) {
        uint16_t counter = (uint16_t) (stats[tb] > UINT16_MAX ? UINT16_MAX : stats[tb]);
        communities[idx++] = ebpf_htonl(((TIE_BREAKER_COMMUNITY + tb) < 2) | (counter));
    }

    if (set_attr(realloc_attr)) {
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