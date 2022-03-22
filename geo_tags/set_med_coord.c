//
// Created by thomas on 15/05/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "router_bgp_config.h"

#include "../prove_stuffs/prove.h"

/* starting point */
uint64_t set_med_coord(args_t *args UNUSED);

PROOF_INSTS(
        uint64_t *nondet_u64__verif(void);

        struct path_attribute *get_attr_from_code(uint8_t code) {
            struct path_attribute *p_attr;
            p_attr = malloc(sizeof(*p_attr) + 8);

            if (!p_attr) return NULL;

            switch (code) {
                case PREFIX_ORIGINATOR:
                    p_attr->code = PREFIX_ORIGINATOR;
                    p_attr->flags = ATTR_TRANSITIVE | ATTR_OPTIONAL;
                    p_attr->length = 8;

                    *(uint64_t *) p_attr->data = nondet_u64__verif();

                    return p_attr;
                default:
                    //p_assert(0);
                    return NULL;
            }
            return NULL;
        }


#define NEXT_RETURN_VALUE PLUGIN_FILTER_UNKNOWN
)


#define TIDYING \
PROOF_INSTS(do { \
    if (attr) free(attr); \
} while (0))


/**
 * Export filter
 */
uint64_t set_med_coord(args_t *args UNUSED) {

    struct path_attribute *med_attr;
    uint8_t buf[sizeof(struct path_attribute) + sizeof(uint32_t)];
    uint64_t med_value;
    med_attr = (struct path_attribute *) buf;

    struct geo_tags *originator_coord;
    struct path_attribute *attr = get_attr_from_code(PREFIX_ORIGINATOR);

    if (!attr) {
        ebpf_print("PREFIX ORIGINATOR not found\n");
        TIDYING;
        return PLUGIN_FILTER_UNKNOWN;
    }

    originator_coord = (struct geo_tags *) attr->data;

    if (!(valid_coord(originator_coord) &&
          valid_coord(&this_router_coordinate))) {
        TIDYING;
        return PLUGIN_FILTER_UNKNOWN;
    }

    med_value = euclidean_distance(originator_coord,
                                   &this_router_coordinate);

    if (med_value < 0 || med_value > 4096) {
        TIDYING;
        return PLUGIN_FILTER_REJECT;
    }

    med_attr->code = MULTI_EXIT_DISC_ATTR_ID;
    med_attr->flags = 0x80;
    med_attr->length = 4;
    memcpy(med_attr->data, &med_value, sizeof(uint32_t));

    PROOF_SEAHORN_INSTS(
            CHECK_MED(med_attr);
            CHECK_IN_BOUNDS_MED(med_attr, 0, 4096);
    )

    if (set_attr(med_attr) != 0) {
        ebpf_print("Failed to set attribute\n");
        TIDYING;
        return PLUGIN_FILTER_UNKNOWN;
    }
    TIDYING;
    next();
    TIDYING;
    return PLUGIN_FILTER_ACCEPT;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t rt_val = set_med_coord(&args);
            PROOF_SEAHORN_INSTS(
                    RET_VAL_FILTERS_CHECKS(rt_val);

            )
            return 0;
        }
)
