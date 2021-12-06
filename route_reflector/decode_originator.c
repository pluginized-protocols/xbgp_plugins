//
// Created by thomas on 20/05/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_rr.h"
#include "../prove_stuffs/prove.h"

/* starting point */
uint64_t decode_originator(args_t *args UNUSED);

PROOF_INSTS(
        uint32_t *nondet_get_u32__verif();
        struct ubpf_peer_info *nondet_gpi__verif();

        void *get_arg(unsigned int arg_type) {
            switch (arg_type) {
                case ARG_CODE: {
                    uint8_t *code;
                    code = malloc(sizeof(*code));
                    *code = ORIGINATOR_ID;
                    return code;
                }
                case ARG_FLAGS: {
                    uint8_t *flags;
                    flags = malloc(sizeof(*flags));
                    *flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;
                    return flags;
                }
                case ARG_DATA: {
                    return nondet_get_u32__verif();
                }
                case ARG_LENGTH: {
                    uint16_t *length;
                }
            }

        }

        struct ubpf_peer_info *gpi(void);

        struct ubpf_peer_info *get_src_peer_info() {
            struct ubpf_peer_info *pf = nondet_gpi__verif();
            pf->peer_type = IBGP_SESSION;
        }

#define NEXT_RETURN_VALUE EXIT_SUCCESS
)


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

    PROOF_SEAHORN_INSTS(
            p_assert(*flags == (ATTR_OPTIONAL | ATTR_TRANSITIVE));
    )

    add_attr(ORIGINATOR_ID, *flags, 4, (uint8_t *) &originator_id);
    return EXIT_SUCCESS;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = decode_originator(&args);
            return ret_val;
        }
)
