//
// Created by thomas on 20/05/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_rr.h"
#include "../prove_stuffs/prove.h"

/* starting point */
uint64_t decode_cluster_list(args_t *args UNUSED);

PROOF_INSTS(
        void *nondet_get_buffer__verif();
        uint16_t *nondet_get_u16__verif();

        void *get_arg(unsigned int arg_type) {
            switch (arg_type) {
                case ARG_CODE: {
                    uint8_t *code;
                    code = malloc(sizeof(*code));
                    *code = CLUSTER_LIST;
                    return code;
                }
                case ARG_FLAGS: {
                    uint8_t *flags;
                    flags = malloc(sizeof(*flags));
                    *flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;
                    return flags;
                }
                case ARG_DATA: {
                    return nondet_get_buffer__verif();
                }
                case ARG_LENGTH: {
                    return nondet_get_u16__verif();
                }
            }

        }

        struct ubpf_peer_info *gpi(void);

        struct ubpf_peer_info *get_src_peer_info() {
            struct ubpf_peer_info *pf = gpi();
            pf->peer_type = IBGP_SESSION;
        }


#define NEXT_RETURN_VALUE EXIT_SUCCESS
)


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

    for (i = 0; i < *len / 4; i++) {
        cluster_list[i] = ebpf_ntohl(in_cluster_list[i]);
    }

    PROOF_SEAHORN_INSTS(
            p_assert(*len % 4 == 0);
            p_assert(*flags == (ATTR_OPTIONAL | ATTR_TRANSITIVE));
    )


    add_attr(CLUSTER_LIST, *flags, *len, (uint8_t *) cluster_list);
    return EXIT_SUCCESS;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = decode_cluster_list(&args);
            return ret_val;
        }
)