//
// Created by thomas on 20/05/20.
//

#include "../../public_bpf.h"
#include "ubpf_api.h"
#include "common_rr.h"

uint64_t decode_cluster_list(bpf_full_args_t *args UNUSED) {

    int i;
    struct ubpf_peer_info *src_info;

    uint8_t *code;
    uint16_t *len;
    uint8_t *flags;
    uint8_t *data;

    uint32_t *cluster_list;
    uint32_t *in_cluster_list;

    code = bpf_get_args(0, args);
    flags = bpf_get_args(1, args);
    data = bpf_get_args(2, args);
    len = bpf_get_args(3, args);

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

    add_attr(CLUSTER_LIST, *flags, 4, (uint8_t *) cluster_list);
    return EXIT_SUCCESS;
}