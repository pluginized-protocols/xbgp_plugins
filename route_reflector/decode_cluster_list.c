//
// Created by thomas on 20/05/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include <bytecode_public.h>
#include "common_rr.h"

uint64_t decode_cluster_list(args_t *args UNUSED) {

    int i;
    struct ubpf_peer_info *src_info;

    uint8_t *code;
    uint16_t *len;
    uint8_t *flags;
    uint8_t *data;

    uint32_t *cluster_list;
    uint32_t *in_cluster_list;

    code = get_arg(ARG_CODE);
    flags = get_arg(ARG_FLAGS);
    data = get_arg(ARG_DATA);
    len = get_arg(ARG_LENGTH);

    src_info = get_src_peer_info();

    if (!src_info || !code || !len || !flags || !data) {
        return EXIT_FAILURE;
    }

    if (src_info->peer_type != IBGP_SESSION) next(); // don't parse CLUSTER_LIST if originated from eBGP session

    if (*code != CLUSTER_LIST) next();

    if (*len % 4 != 0) return 0;

    cluster_list = ctx_malloc(*len);
    if (!cluster_list) return EXIT_FAILURE;

    in_cluster_list = (uint32_t *) data;

    for(i = 0; i < *len/4; i++) {
        cluster_list[i] = ebpf_ntohl(in_cluster_list[i]);
    }

    add_attr(CLUSTER_LIST, *flags, *len, (uint8_t *) cluster_list);
    return EXIT_SUCCESS;
}