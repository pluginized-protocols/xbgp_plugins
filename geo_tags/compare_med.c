//
// Created by thomas on 20/02/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "router_bgp_config.h"

#include "../prove_stuffs/prove.h"

/* starting point */
uint64_t compare_med(args_t *args __attribute__((unused)));


PROOF_INSTS(
        uint64_t nondet_get_int__verif(void);

        struct path_attribute *get_attr_from_code_by_route(uint8_t code, int rte) {
            if (code != BA_GEO_TAG) return NULL;
            struct path_attribute *p_attr;

            p_attr = malloc(sizeof(*p_attr) + 8);
            if (!p_attr) return NULL;

            p_attr->code = BA_GEO_TAG;
            p_attr->flags = ATTR_TRANSITIVE | ATTR_OPTIONAL;
            p_attr->length = 8;
            *((uint64_t *) p_attr->data) = nondet_get_int__verif();

            return p_attr;
        }

)

#define TIDYING \
PROOF_INSTS(do {            \
   if (new_attr) free(new_attr); \
   if (old_attr) free(old_attr); \
} while(0);)


/**
 * Compare geo attribute instead of the med. This pluglet will be played
 * in the "med position" of the BGP decision process.
 * @param args unused. This function uses API calls to retrieve the attribute to compare
 * @return RTE_OLD if the old route is still the best
 *         RTE_NEW if the new route is better than the old one
 *         RTE_UNKNOWN unable to decide with geographical attribute here.
 */
uint64_t compare_med(args_t *args __attribute__((unused))) {

    uint64_t new_dist, old_dist;
    struct path_attribute *new_attr;
    struct path_attribute *old_attr;

    geo_tags_t *new_geo;
    geo_tags_t *old_geo;

    new_attr = get_attr_from_code_by_route(BA_GEO_TAG, BGP_ROUTE_TYPE_NEW);
    old_attr = get_attr_from_code_by_route(BA_GEO_TAG, BGP_ROUTE_TYPE_OLD);

    if (!new_attr || !old_attr) {
        ebpf_print("Wow! Trouble to get attributes");
        TIDYING;
        return BGP_ROUTE_TYPE_UNKNOWN;
    }

    new_geo = (geo_tags_t *) new_attr->data;
    old_geo = (geo_tags_t *) old_attr->data;

    if (!(valid_coord(new_geo) &&
          valid_coord(old_geo) &&
          valid_coord(&this_router_coordinate))) {
        TIDYING;
        return BGP_ROUTE_TYPE_UNKNOWN;
    }

    new_dist = euclidean_distance(new_geo, &this_router_coordinate);
    old_dist = euclidean_distance(old_geo, &this_router_coordinate);

    if (new_dist > old_dist) {
        ebpf_print("Old route is kept\n");
        TIDYING;
        return BGP_ROUTE_TYPE_OLD;
    }
    if (new_dist < old_dist) {
        ebpf_print("New route is used\n");
        TIDYING;
        return BGP_ROUTE_TYPE_NEW;
    }

    TIDYING;
    return BGP_ROUTE_TYPE_UNKNOWN;
}


PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val;

            ret_val = compare_med(&args);

            PROOF_SEAHORN_INSTS(
                    p_assert(ret_val == BGP_ROUTE_TYPE_OLD ||
                             ret_val == BGP_ROUTE_TYPE_NEW ||
                             ret_val == BGP_ROUTE_TYPE_UNKNOWN);
            );
            return 0;
        }
)