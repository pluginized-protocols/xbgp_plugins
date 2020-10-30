//
// Created by thomas on 17/04/20.
//

#include "../public_bpf.h"
#include "ubpf_api.h"

#define nano_sec(timer) (((timer)->tv_sec * 1000000000) + (timer)->tv_nsec)

uint64_t on_update_send_fini(bpf_full_args_t *args) {
    struct path_attribute *attribute;
    struct timespec spec;
    struct timespec final;
    uint64_t *nanosec;
    uint32_t *peer_router_id;
    uint32_t to_peer_id;
    uint64_t diff;

    uint8_t monit_data[16];
    int offset = 0;

    if (((void *) args->return_value) == NULL) {
        // nothing has been sent...
        return EXIT_FAILURE;
    }

    if (get_time(&spec) != 0) {
        return EXIT_FAILURE;
    }

    attribute = get_attr_from_code(43);
    if (!attribute) return EXIT_FAILURE;

    nanosec = (uint64_t *) attribute->data;
    peer_router_id = (uint32_t *) (attribute->data + 8);
    to_peer_id = get_peer_router_id();
    diff = nano_sec(&final) - *nanosec;

    *((uint64_t *)monit_data) = diff;
    offset += 8;
    *((uint32_t *)(monit_data + offset)) = *peer_router_id;
    offset += 4;
    *((uint32_t *) (monit_data + offset)) = to_peer_id;

    send_to_monitor(monit_data, 16, 0);
    return EXIT_SUCCESS;
}