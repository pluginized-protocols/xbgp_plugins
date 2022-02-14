//
// Created by thomas on 11/02/22.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "propagation_time_common.h"

uint64_t decode_arrival_time(args_t *args UNUSED) {
    struct ubpf_peer_info *src_info = NULL;
    char attr_space[sizeof(struct path_attribute) + sizeof(struct attr_arrival)];
    struct path_attribute *attr;
    struct attr_arrival *arrival;

    uint8_t *code = NULL;
    uint16_t *len = NULL;
    uint8_t *flags = NULL;
    uint8_t *data = NULL;

    code = get_arg(ARG_CODE);
    flags = get_arg(ARG_FLAGS);
    data = get_arg(ARG_DATA);
    len = get_arg(ARG_LENGTH);

    src_info = get_src_peer_info();

    if (!src_info || !code || !len || !flags || !data) {
        return EXIT_FAILURE;
    }

    if (src_info->peer_type != IBGP_SESSION) {
        next();
    }

    if (*code != ARRIVAL_TIME_ATTR) {
        next();
    }

    attr = (struct path_attribute *) attr_space;
    arrival = (struct attr_arrival *) attr->data;

    /* read seconds */
    arrival->arrival_time.tv_sec = read_u64(data);
    /* read nanosecs */
    arrival->arrival_time.tv_nsec = read_u64(data);
    /* read origin AS */
    arrival->from_as = read_u32(data);


    if (set_attr(attr) != 0) return EXIT_FAILURE;

    return EXIT_SUCCESS;
}