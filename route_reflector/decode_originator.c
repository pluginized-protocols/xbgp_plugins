//
// Created by thomas on 20/05/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include <bytecode_public.h>
#include "common_rr.h"

uint64_t decode_originator(args_t *args UNUSED) {

    uint8_t *code;
    uint16_t *len;
    uint8_t *flags;
    uint8_t *data;
    struct ubpf_peer_info *src_info;

    uint32_t originator_id;

    code = get_arg(ARG_CODE);
    flags = get_arg(ARG_FLAGS);
    data = get_arg(ARG_DATA);
    len = get_arg(ARG_LENGTH);

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