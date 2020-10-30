//
// Created by thomas on 20/05/20.
//

#include "../../public_bpf.h"
#include "ubpf_api.h"
#include "common_rr.h"

uint64_t decode_originator(bpf_full_args_t *args UNUSED) {

    uint8_t *code;
    uint16_t *len;
    uint8_t *flags;
    uint8_t *data;
    struct ubpf_peer_info *src_info;

    uint32_t originator_id;

    code = bpf_get_args(0, args);
    flags = bpf_get_args(1, args);
    data = bpf_get_args(2, args);
    len = bpf_get_args(3, args);

    src_info = get_src_peer_info();

    if (!code || !len || !flags || !data) {
        return EXIT_FAILURE;
    }

    if (src_info->peer_type != IBGP_SESSION) next(); // don't parse ORIGINATOR_LIST if originated from eBGP session

    if (*code != ORIGINATOR_ID) next();

    if (*len != 4) return 0;

    originator_id = ebpf_ntohl(*((uint32_t *) data));
    add_attr(ORIGINATOR_ID, *flags, 4, (uint8_t *) &originator_id);
    return EXIT_SUCCESS;
}