//
// Created by thomas on 10/02/22.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "propagation_time_common.h"

/* main entry point */
uint64_t encode_arrival_time_attr(args_t *args);


uint64_t encode_arrival_time_attr(args_t *args UNUSED) {
    struct ubpf_peer_info *dst_info;
    struct timespec *in_time;
    struct path_attribute *attribute;
    struct attr_arrival *arrival;
    char attr_buf[ARRIVAL_TIME_ATTR_LEN + ATTR_HDR_LEN];
    char *attr = attr_buf;
    int nb_peer;

    attribute = get_attr();

    dst_info = get_peer_info(&nb_peer);
    if (!dst_info) {
        next();
        return 0;
    }

    if (!attribute) {
        next();
        return 0;
    }

    if (attribute->code != ARRIVAL_TIME_ATTR) {
        next();
        return 0;
    }

    arrival = (struct attr_arrival *) attribute->data;
    in_time = &arrival->arrival_time;

    if (dst_info->peer_type != IBGP_SESSION) {
        /*
         * this attribute is only written
         * to an iBGP peer
         */
        next();
        return 0;
    }

    /* attr flags */
    write_u8(attr, ATTR_OPTIONAL);
    /* attr type */
    write_u8(attr, ARRIVAL_TIME_ATTR);
    /* attr length */
    write_u8(attr, ARRIVAL_TIME_ATTR_LEN);

    /* write the attribute */
    write_u64(attr, in_time->tv_sec);
    write_u64(attr, in_time->tv_nsec);
    write_u32(attr, arrival->from_as);

    /* make sure the offset pointer
     * has not overflowed nor underflow */
    assert(attr == attr_buf + sizeof(attr_buf));


    if (write_to_buffer((uint8_t *)attr_buf, sizeof(attr_buf)) != 0) {
        return 0;
    }

    return sizeof(attr_buf);
}

