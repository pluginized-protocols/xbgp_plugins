//
// Created by thomas on 15/05/20.
//


#include "public_bpf.h"
#include "router_bgp_config.h"
#include "ubpf_api.h"

static __always_inline uint64_t euclidean_distance(const int32_t x1[2], const int32_t x2[2]) {

    uint64_t a = (x2[0] - x1[0]);
    uint64_t b = (x2[1] - x1[1]);
    return ebpf_sqrt((a * a) + (b * b), 6);
}


/**
 * Export filter
 */
uint64_t compute_med(bpf_full_args_t *args UNUSED) {

    struct path_attribute med_attr;
    uint32_t med_value;

    struct geo_tags *originator_coord;
    struct path_attribute *attr = get_attr_from_code(PREFIX_ORIGINATOR);

    if (!attr) {
        ebpf_print("PREFIX ORIGINATOR not found\n");
        return FAIL;
    }

    originator_coord = (struct geo_tags *) attr->data;

    med_value = (uint32_t) euclidean_distance(originator_coord->coordinates,
                                              this_router_coordinate.coordinates);

    med_attr.code = MED_ATTR;
    med_attr.flags = 0x80;
    med_attr.len = 4;
    med_attr.data = (uint8_t *) &med_value;

    if (set_attr(&med_attr) != 0) {
        ebpf_print("Failed to set attribute\n");
        return FAIL;
    }

    next();
    return PLUGIN_FILTER_ACCEPT;
}
