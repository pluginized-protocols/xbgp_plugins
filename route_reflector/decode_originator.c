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
        uint16_t nondet_u16__verif(void);
        uint8_t nondet_u8(void);
        static uint16_t data_length = 0;

        void *get_arg(unsigned int arg_type) {
            switch (arg_type) {
                case ARG_CODE: {
                    uint8_t *code;
                    code = malloc(sizeof(*code));
                    *code = nondet_u8();
                    return code;
                }
                case ARG_FLAGS: {
                    uint8_t *flags;
                    flags = malloc(sizeof(*flags));
                    *flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;
                    return flags;
                }
                case ARG_DATA: {
                    if (data_length == 0) return NULL;
                    uint8_t *data = malloc(data_length);

                    return data;
                }
                case ARG_LENGTH: {
                    uint16_t *length;
                    if (data_length == 0) {
                        data_length = nondet_u16__verif();
                        p_assume(data_length % 4 == 0);
                    }

                    length = malloc(sizeof(*length));
                    if (!length) return NULL;

                    *length = data_length;
                    return length;
                }
            }

        }

        struct ubpf_peer_info *get_src_peer_info() {
            struct ubpf_peer_info *pf;

            pf = malloc(sizeof(*pf));
            if (!pf) return NULL;

            pf->peer_type = IBGP_SESSION;
            return pf;
        }

#define NEXT_RETURN_VALUE EXIT_SUCCESS
)


#define TIDYING() \
PROOF_INSTS(do {\
 if (code) free(code); \
 if (len) free(len);   \
 if (flags) free(flags); \
 if (data) free(data); \
 if (src_info) free(src_info); \
} while(0))


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

    if (!code || !len || !flags || !data) {
        TIDYING();
        return EXIT_FAILURE;
    }

    if (*code != ORIGINATOR_ID) {
        TIDYING();
        next();
    }

    src_info = get_src_peer_info();
    if (!src_info || src_info->peer_type != IBGP_SESSION) {
        TIDYING();
        next(); // don't parse ORIGINATOR_LIST if originated from eBGP session
    }

    if (*len != 4) return 0;

    originator_id = ebpf_ntohl(*((uint32_t *) data));

    PROOF_SEAHORN_INSTS(
            p_assert(*flags == (ATTR_OPTIONAL | ATTR_TRANSITIVE));
    )

    add_attr(ORIGINATOR_ID, *flags, 4, (uint8_t *) &originator_id);
    TIDYING();
    return EXIT_SUCCESS;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = decode_originator(&args);
            return ret_val;
        }
)
