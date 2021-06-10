//
// Created by thomas on 15/05/20.
//


#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include <bytecode_public.h>
#include "router_bgp_config.h"

#include "../prove_stuffs/prove.h"

#ifdef PROVERS_SH
#include "../prove_stuffs/mod_ubpf_api.c"

#define next() return PLUGIN_FILTER_UNKNOWN

#endif

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

#ifdef PROVERS_SH
    CHECK_MED(med_attr);
    CHECK_IN_BOUNDS_MED(med_attr, 0, 4096);
#endif

    if (set_attr(med_attr) != 0) {
        ebpf_print("Failed to set attribute\n");
        return PLUGIN_FILTER_UNKNOWN;
    }

    next();
    return PLUGIN_FILTER_ACCEPT;
}

#ifdef PROVERS_SH
int main(void) {
    args_t args = {};
    uint64_t rt_val = compute_med(&args);

    RET_VAL_FILTERS_CHECKS(rt_val);

    return 0;
}
#endif
