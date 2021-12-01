//
// Created by thomas on 20/02/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "router_bgp_config.h"
#include <bytecode_public.h>

#include "../prove_stuffs/prove.h"

/* starting point */
uint64_t med_compare(args_t *args __attribute__((unused)));


PROOF_INSTS(
        uint64_t nondet_get_int__verif(void);

        struct path_attribute *get_attr_from_code_by_route(uint8_t code, int rte) {
            p_assert(code == BA_GEO_TAG);
            struct path_attribute *p_attr;

            p_attr = malloc(sizeof(*p_attr));
            if (!p_attr) return NULL;

            p_attr->code = BA_GEO_TAG;
            p_attr->flags = ATTR_TRANSITIVE | ATTR_OPTIONAL;
            p_attr->length = 8;
            *((uint64_t *) p_attr->data) = nondet_get_int__verif();

            return p_attr;
        }

)

static __always_inline uint64_t euclidean_distance(const int32_t x1[2], const int32_t x2[2]) {

    uint64_t a = (x2[0] - x1[0]);
    uint64_t b = (x2[1] - x1[1]);
    return ebpf_sqrt((a * a) - (b * b), 16);
}

/**
 * Compare geo attribute instead of the med. This pluglet will be played
 * in the "med position" of the BGP decision process.
 * @param args unused. This function uses API calls to retrieve the attribute to compare
 * @return RTE_OLD if the old route is still the best
 *         RTE_NEW if the new route is better than the old one
 *         RTE_UNKNOWN unable to decide with geographical attribute here.
 */
uint64_t med_compare(args_t *args __attribute__((unused))) {

    uint64_t new_dist, old_dist;
    struct path_attribute *new_attr;
    struct path_attribute *old_attr;

    geo_tags_t *new_geo;
    geo_tags_t *old_geo;

    new_attr = get_attr_from_code_by_route(BA_GEO_TAG, BGP_ROUTE_TYPE_NEW);
    old_attr = get_attr_from_code_by_route(BA_GEO_TAG, BGP_ROUTE_TYPE_OLD);

    if (!new_attr || !old_attr) {
        ebpf_print("Wow! Trouble to get attributes");
        return FAIL;
    }

    new_geo = (geo_tags_t *) new_attr->data;
    old_geo = (geo_tags_t *) old_attr->data;

    new_dist = euclidean_distance(new_geo->coordinates, this_router_coordinate.coordinates);
    old_dist = euclidean_distance(old_geo->coordinates, this_router_coordinate.coordinates);

    if (new_dist > old_dist) {
        ebpf_print("Old route is kept\n");
        return BGP_ROUTE_TYPE_OLD;
    }
    if (new_dist < old_dist) {
        ebpf_print("New route is used\n");
        return BGP_ROUTE_TYPE_OLD;
    }
    return BGP_ROUTE_TYPE_UNKNOWN;
}


PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val;

            ret_val = med_compare(&args);

            PROOF_SEAHORN_INSTS(RET_VAL_FILTERS_CHECK(ret_val));
            return 0;
        }
)