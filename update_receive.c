//
// Created by thomas on 17/04/20.
//

#include "../public_bpf.h"
#include "ubpf_api.h"

#define SEC_TO_NANOSEC_MULTIPLIER 1000000000

uint64_t on_update_receive(bpf_full_args_t *args UNUSED) {

    uint8_t buf[12];
    uint64_t nanosec;
    uint32_t peer_id;
    struct timespec spec = {0};

    if (get_time(&spec) != 0) {
        // can't retrieve time ????
    }

    // assuming the system hasn't been running for more than 544 years
    nanosec = (spec.tv_sec * SEC_TO_NANOSEC_MULTIPLIER) + spec.tv_nsec;
    peer_id = get_peer_router_id();

    *((uint64_t *) buf) = nanosec;
    *((uint32_t *)(buf + 8)) = peer_id;

    return add_attr(43, 0x80, 12, buf) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}