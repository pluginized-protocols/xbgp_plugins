//
// Created by thomas on 11/02/22.
//


#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "propagation_time_common.h"
#include "../prove_stuffs/prove.h"


uint64_t compute_arrival_time(args_t *);

PROOF_INSTS(
#define NEXT_RETURN_VALUE FAIL
        uint16_t nondet_u16(void);
        uint8_t nondet_u8(void);
        unsigned int nondet_uint(void);
        long nondet_long(void);

        struct path_attribute *get_attr() {
            uint16_t len;
            struct path_attribute *p_attr;
            len = nondet_u16();
            p_attr = malloc(sizeof(*p_attr) + len);

            if (p_attr == NULL) return NULL;

            p_attr->flags = ATTR_OPTIONAL|ATTR_TRANSITIVE;
            p_attr->code = ARRIVAL_TIME_ATTR;
            p_attr->length = sizeof(struct attr_arrival);

            return p_attr;
        }

        struct path_attribute *get_attr_from_code(uint8_t code) {
            struct path_attribute *attr;
            attr = get_attr();
            return attr;
        }

        int get_realtime(struct timespec *spec) {
            spec->tv_sec = nondet_uint();
            spec-> tv_nsec = nondet_long();
            return 0;
        }

        struct ubpf_peer_info *get_src_peer_info() {
            struct ubpf_peer_info *pf;

            pf = malloc(sizeof(*pf));
            if (!pf) return NULL;

            pf->peer_type = nondet_u8();
            return pf;
        }
        )

#define TIDYING() \
PROOF_INSTS(do {            \
if (src_info) free(src_info); \
if (attr) free(attr); \
} while(0))

uint64_t compute_arrival_time(args_t *args UNUSED) {
    char attr_space[sizeof(struct path_attribute) + sizeof(struct attr_arrival)];
    struct path_attribute *arrival_attr, *attr;
    struct attr_arrival *arrival_data;
    struct ubpf_peer_info *src_info = NULL;

    arrival_attr = (struct path_attribute *) attr_space;
    arrival_data = (struct attr_arrival *) arrival_attr->data;

    attr = get_attr_from_code(ARRIVAL_TIME_ATTR);
    if (attr != NULL) {
        /*
         * If the attribute is already set, don't
         * overwrite the attribute already set.
         */
        TIDYING();
        next();
        return PLUGIN_FILTER_UNKNOWN;
    }


    if (get_realtime(&arrival_data->arrival_time) != 0) {
        TIDYING();
        next();
        return PLUGIN_FILTER_UNKNOWN;
    }

    src_info = get_src_peer_info();
    if (!src_info) {
        TIDYING();
        next();
        return PLUGIN_FILTER_UNKNOWN;
    }

    /* the attribute is only computed for
     * routes coming from eBGP sessions */
    if (src_info->peer_type != EBGP_SESSION) {
        TIDYING();
        next();
        return PLUGIN_FILTER_UNKNOWN;
    }

    arrival_attr->flags = ATTR_OPTIONAL|ATTR_TRANSITIVE;
    arrival_attr->code = ARRIVAL_TIME_ATTR;
    arrival_attr->length = sizeof(struct attr_arrival);

    arrival_data->from_as = src_info->as;

    PROOF_SEAHORN_INSTS(
            CHECK_ATTR_FORMAT(arrival_attr, sizeof(struct attr_arrival));
    )

    if (set_attr(arrival_attr) != 0) {
        ebpf_print("Failed to set arrival attribute");
        TIDYING();
        next();
        return PLUGIN_FILTER_UNKNOWN;
    }

    /* this import filter doesn't decide anything.
     * we continue to the other filter if any */
    TIDYING();
    next();
    return PLUGIN_FILTER_UNKNOWN;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = compute_arrival_time(&args);

            p_assert(ret_val == 0 ||
            ret_val == PLUGIN_FILTER_UNKNOWN);

            return 0;
        }
        )