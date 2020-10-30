//
// Created by thomas on 20/02/20.
//

#include "public_bpf.h"
#include "ubpf_api.h"

typedef struct geo_tags {
    int32_t coordinates[2];
} geo_tags_t;

static geo_tags_t this_router_coordinate = {.coordinates = {1, 2}};

static __always_inline uint64_t euclidean_distance(const int32_t x1[2], const int32_t x2[2]) {

    uint64_t a = (x2[0] - x1[0]);
    uint64_t b = (x2[1] - x1[1]);
    return ebpf_sqrt((a*a) - (b*b), 16);
}

/**
 * Compare geo attribute instead of the med. This pluglet will be played
 * in the "med position" of the BGP decision process.
 * @param args unused. This function uses API calls to retrieve the attribute to compare
 * @return RTE_OLD if the old route is still the best
 *         RTE_NEW if the new route is better than the old one
 *         RTE_UNKNOWN unable to decide with geographical attribute here.
 */
uint64_t med_compare(bpf_full_args_t *args __attribute__((unused))) {

    uint64_t new_dist, old_dist;
    struct path_attribute *new_attr;
    struct path_attribute *old_attr;

    geo_tags_t *new_geo;
    geo_tags_t *old_geo;

    new_attr = get_attr_by_code_from_rte(BA_GEO_TAG, 0);
    old_attr = get_attr_by_code_from_rte(BA_GEO_TAG, 1);

    if (!new_attr || !old_attr) {
        ebpf_print("Wow! Trouble to get attributes");
        return FAIL;
    }

    new_geo = (geo_tags_t *) new_attr->data;
    old_geo = (geo_tags_t *) old_attr->data;

    new_dist = euclidean_distance(new_geo->coordinates, this_router_coordinate.coordinates);
    old_dist = euclidean_distance(old_geo->coordinates, this_router_coordinate.coordinates);

    if (new_dist > old_dist){
        ebpf_print("Old route is kept\n");
        return RTE_OLD;
    }
    if (new_dist < old_dist){
        ebpf_print("New route is used\n");
        return RTE_NEW;
    }
    return RTE_UNK;
}