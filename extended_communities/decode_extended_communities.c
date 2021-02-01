//
// Created by thomas on 20/05/20.
//

#include <stdint.h>
#include <bytecode_public.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_ext_comm.h"

uint64_t decode_extended_communities(args_t *args UNUSED) {

    int i;

    uint8_t *code;
    uint16_t *len;
    uint8_t *flags;
    uint8_t *data;

    uint64_t *in_ext_communitites;
    uint64_t *decoded_ext_communitities;

    ebpf_print("[WARNING] This code won't work!\n");
    code = get_arg(ARG_CODE);  // refactor
    flags = get_arg(ARG_FLAGS);
    data = get_arg(ARG_DATA);
    len = get_arg(ARG_LENGTH);

    if (!code || !len || !flags || !data) {
        return EXIT_FAILURE;
    }

    if (*code != EXTENDED_COMMUNITIES) next();

    if (*len % 8 != 0) {
        // malformed extended attribute
        return EXIT_FAILURE;
    }

    in_ext_communitites = (uint64_t *)data;

    decoded_ext_communitities = ctx_malloc(*len);
    if (!decoded_ext_communitities) next();

    for (i = 0; i < *len/8; i++) {
        decoded_ext_communitities[i] = ebpf_ntohll(in_ext_communitites[i]);
    }

    add_attr(EXTENDED_COMMUNITIES, *flags, *len, (uint8_t *)decoded_ext_communitities);

    return EXIT_SUCCESS;
}