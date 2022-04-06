//
// Created by thomas on 14/02/22.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "propagation_time_common.h"
#include "../prove_stuffs/prove.h"
#ifdef PROVERS
#include <limits.h>
#endif

/* entry point */
uint64_t encode_propagation_time_communities(args_t *args UNUSED);

PROOF_INSTS(
#define NEXT_RETURN_VALUE FAIL
        unsigned int nondet_uint(void);
        long nondet_long(void);

        struct path_attribute *get_attr_from_code(uint8_t code) {
            unsigned int ndet_len = nondet_uint();
            if (code != COMMUNITY_ATTR_ID) {
                return NULL;
            }
            struct path_attribute *communities = malloc(sizeof(struct path_attribute) + ndet_len);

            if (!communities) return NULL;

            communities->length = ndet_len % (UINT16_MAX + 1);
            return communities;
        }

        struct path_attribute *get_attr(void) {
            struct path_attribute *p_attr = malloc(sizeof(struct path_attribute) + sizeof(struct attr_arrival));
            if (!p_attr) return NULL;
            p_attr->code = ARRIVAL_TIME_ATTR;
            struct attr_arrival *aa = (struct attr_arrival*)p_attr->data;
            aa->arrival_time.tv_sec = 0;
            aa->arrival_time.tv_nsec = 0;
            return p_attr;
        }

        struct ubpf_peer_info *get_src_peer_info() {
            struct ubpf_peer_info *pf;

            pf = malloc(sizeof(*pf));
            if (!pf) return NULL;

            pf->peer_type = EBGP_SESSION;
            return pf;
        }

        struct ubpf_peer_info *get_peer_info(int *nb_peers) {
            return get_src_peer_info();
        }

        int get_realtime(struct timespec *spec) {
            spec->tv_sec = INT_MAX;
            spec-> tv_nsec = LONG_MAX;
            return 0;
        }
        )

#define TIDYING() \
PROOF_INSTS(do {            \
if (communities) free(communities); \
if (dst_info) free(dst_info); \
if (communities_new) free(communities_new); \
if (arrival_time) free(arrival_time); \
} while(0);)

#define MEM_COMMUNITIES 789
#define MEM_COMMUNITIES_SIZE 4096

static __always_inline void *get_mem() {
    void *mem;

    mem = ctx_shmget(MEM_COMMUNITIES);
    if (mem) { return mem; }
    return ctx_shmnew(MEM_COMMUNITIES, MEM_COMMUNITIES_SIZE);
}

uint64_t encode_propagation_time_communities(args_t *args UNUSED) {
    struct path_attribute *communities;
    struct path_attribute *arrival_time;
    struct ubpf_peer_info *dst_info = NULL;
    struct timespec out_time, difftime;
    struct timespec *in_time;
    struct attr_arrival *arrival;
    int nb_peer;
    unsigned int communities_length;
    unsigned int old_communities_length;
    struct path_attribute *communities_new = NULL;
    uint16_t propagation_time;

    communities = get_attr_from_code(COMMUNITY_ATTR_ID);
    arrival_time = get_attr_from_code(ARRIVAL_TIME_ATTR);

    dst_info = get_peer_info(&nb_peer);

    if (!arrival_time) {
        TIDYING();
        next();
        return 0;
    }

    /* if the peer is not EBGP, then skip also */
    if (dst_info->peer_type != EBGP_SESSION) {
        TIDYING();
        next();
        return 0;
    }

    /* get the time of day (NTP) */
    if (get_realtime(&out_time) != 0) {
        TIDYING();
        return PLUGIN_FILTER_UNKNOWN;
    }

    arrival = (struct attr_arrival *) arrival_time->data;
    in_time = &arrival->arrival_time;


    /* compute total time spent in the AS */
    timespec_diff(&out_time, in_time, &difftime);

    propagation_time = timespec2ms(&difftime);
    if (propagation_time == 0) {
        ebpf_print("Propagation time took longer than 65s !\n");
    }

    /* we add a new community value */
    old_communities_length = communities ? communities->length : 0;
    communities_length = old_communities_length + 4;

    if (communities_length > MEM_COMMUNITIES_SIZE) {
        ebpf_print("COMMUNITIES SIZE OVERFLOWS %d > MAX (%u) !",
                   LOG_INT(communities_length),
                   LOG_UINT(MEM_COMMUNITIES_SIZE));
        TIDYING();
        return 0;
    }

    communities_new = get_mem(); //ctx_malloc(communities_length);
    if (!communities_new) {
        TIDYING();
        return 0;
    }

    communities_new->code = COMMUNITY_ATTR_ID;
    communities_new->flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;
    communities_new->length = communities_length;

    if (communities_length > 255) {
        communities_new->flags |= ATTR_EXT_LEN;
    }

    if (communities) {
        /* recreate communities */
        ebpf_memcpy(communities_new->data, communities->data, communities->length);
    }

    *((uint32_t *)(communities_new->data + old_communities_length)) =
            (ebpf_htons(propagation_time) << 16) | COMMUNITY_ARRIVAL_TAG_BE;

    TIDYING();
    /* time to create the attribute to be sent to the wire */

    if (set_attr(communities_new) != 0) {
        ebpf_print("set_attr failed\n");
    }
    return PLUGIN_FILTER_UNKNOWN;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = encode_propagation_time_communities(&args);

            p_assert(ret_val == 0 ||
            ret_val == PLUGIN_FILTER_UNKNOWN ||
            ret_val > 0);

            ctx_shmrm(MEM_COMMUNITIES);

            return 0;
        }
        )