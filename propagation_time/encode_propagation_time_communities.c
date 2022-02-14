//
// Created by thomas on 14/02/22.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "propagation_time_common.h"

/* entry point */
uint64_t encode_propagation_time_communities(args_t *args UNUSED);

uint64_t encode_propagation_time_communities(args_t *args UNUSED) {
    struct path_attribute *communities;
    struct path_attribute *arrival_time;
    struct ubpf_peer_info *dst_info;
    struct timespec out_time, difftime;
    struct timespec *in_time;
    struct attr_arrival *arrival;
    int nb_peer;
    int communities_length;
    int old_communities_length;
    uint8_t *communities_new;
    uint16_t propagation_time;

    communities = get_attr_from_code(COMMUNITY_ATTR_ID);
    arrival_time = get_attr();

    dst_info = get_peer_info(&nb_peer);

    if (!arrival_time) {
        next();
        return 0;
    }

    /* the current attribute to be processed
     * is not the one we expect */
    if (arrival_time->code != ARRIVAL_TIME_ATTR) {
        next();
        return 0;
    }

    /* if the peer is not EBGP, then skip also */
    if (dst_info->peer_type != EBGP_SESSION) {
        next();
        return 0;
    }

    /* get the time of day (NTP) */
    if (get_realtime(&out_time) != 0) {
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

    /* todo maybe should realloc communities->data */
    communities_new = ctx_malloc(communities_length);
    if (!communities_new) {
        return 0;
    }

    if (communities) {
        /* recreate communities */
        ebpf_memcpy(communities_new, communities->data, communities->length);
    }

    *((uint32_t *)(communities_new + old_communities_length)) =
            ebpf_htonl((COMMUNITY_ARRIVAL_TAG << 2) | propagation_time);


    /* time to create the attribute to be sent to the wire */
    return (write_attr(COMMUNITY_ATTR_ID, ATTR_OPTIONAL|ATTR_TRANSITIVE,
                  communities_length, communities_new));
}