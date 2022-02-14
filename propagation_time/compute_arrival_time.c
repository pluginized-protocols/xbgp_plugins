//
// Created by thomas on 11/02/22.
//


#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "propagation_time_common.h"


uint64_t compute_arrival_time(args_t *);

uint64_t compute_arrival_time(args_t *args UNUSED) {
    char attr_space[sizeof(struct path_attribute) + sizeof(struct attr_arrival)];
    struct path_attribute *arrival_attr;
    struct attr_arrival *arrival_data;
    struct ubpf_peer_info *src_info;

    arrival_attr = (struct path_attribute *) attr_space;
    arrival_data = (struct attr_arrival *) arrival_attr->data;

    if (get_attr_from_code(ARRIVAL_TIME_ATTR) == NULL) {
        /*
         * If the attribute is already set, don't
         * overwrite the attribute already set.
         */
        next();
        return PLUGIN_FILTER_UNKNOWN;
    }


    if (get_realtime(&arrival_data->arrival_time) != 0) {
        next();
        return PLUGIN_FILTER_UNKNOWN;
    }

    src_info = get_src_peer_info();
    if (!src_info) {
        next();
        return PLUGIN_FILTER_UNKNOWN;
    }

    /* the attribute is only computed for
     * routes coming from eBGP sessions */
    if (src_info->peer_type != EBGP_SESSION) {
        next();
        return PLUGIN_FILTER_UNKNOWN;
    }

    arrival_attr->flags = ATTR_OPTIONAL|ATTR_TRANSITIVE;
    arrival_attr->code = ARRIVAL_TIME_ATTR;
    arrival_attr->length = sizeof(struct attr_arrival);

    arrival_data->from_as = src_info->as;

    if (set_attr(arrival_attr) != 0) {
        ebpf_print("Failed to set arrival attribute");
        next();
        return PLUGIN_FILTER_UNKNOWN;
    }

    /* this import filter doesn't decide anything.
     * we continue to the other filter if any */
    next();
    return PLUGIN_FILTER_UNKNOWN;
}

