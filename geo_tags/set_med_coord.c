//
// Created by thomas on 15/05/20.
//


#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include <bytecode_public.h>
#include "router_bgp_config.h"

#include "../prove_stuffs/prove.h"

uint64_t compute_med(args_t *args UNUSED);

PROOF_INSTS(
        uint8_t *nondet_get_buf__verif();

        struct path_attribute *get_attr_from_code(uint8_t code) {
            struct path_attribute *p_attr;
            p_attr = malloc(sizeof(*p_attr));

            switch (code) {
                case PREFIX_ORIGINATOR:
                    p_attr->code = PREFIX_ORIGINATOR;
                    p_attr->flags = ATTR_TRANSITIVE | ATTR_OPTIONAL;
                    p_attr->length = 4;
                    memcpy(p_attr->data, nondet_get_buf__verif(), p_attr->length);
                    break;
                default:
                    //p_assert(0);
                    return NULL;
            }
            return NULL;
        }


#define NEXT_RETURN_VALUE PLUGIN_FILTER_UNKNOWN
)

static __always_inline uint64_t euclidean_distance(const int32_t x1[2], const int32_t x2[2]) {

    uint64_t a = (x2[0] - x1[0]);
    uint64_t b = (x2[1] - x1[1]);
    return ebpf_sqrt((a * a) + (b * b), 6);
}

void *memcpy(void *dst, const void *src, unsigned long size);

/**
 * Export filter
 */
uint64_t compute_med(args_t *args UNUSED) {

    struct path_attribute *med_attr;
    uint8_t buf[sizeof(struct path_attribute) + sizeof(uint32_t)];
    uint32_t med_value;
    med_attr = (struct path_attribute *) buf;

    struct geo_tags *originator_coord;
    struct path_attribute *attr = get_attr_from_code(PREFIX_ORIGINATOR);

    if (!attr) {
        ebpf_print("PREFIX ORIGINATOR not found\n");
        return PLUGIN_FILTER_UNKNOWN;
    }

    originator_coord = (struct geo_tags *) attr->data;

    med_value = (uint32_t) euclidean_distance(originator_coord->coordinates,
                                              this_router_coordinate.coordinates);

    if (med_value < 0 || med_value > 4096) return PLUGIN_FILTER_REJECT;

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
        return PLUGIN_FILTER_UNKNOWN;
    }

    next();
    return PLUGIN_FILTER_ACCEPT;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t rt_val = compute_med(&args);
            PROOF_SEAHORN_INSTS(
                    RET_VAL_FILTERS_CHECKS(rt_val);

            )
            return 0;
        }
)