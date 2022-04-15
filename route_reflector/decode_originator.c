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
                    uint8_t *data = malloc(data_length);

                    return data;
                }
                case ARG_LENGTH: {
                    uint16_t *length;
                    if (data_length == 0) {
                        data_length = nondet_u16__verif();
                        p_assume(data_length > 0);
                    }

                    length = malloc(sizeof(*length));
                    if (!length) return NULL;

                    *length = data_length;
                    return length;
                }
                default:
                    return NULL;
            }

        }

        struct ubpf_peer_info *get_src_peer_info() {
#ifndef PROVERS_SEAHORN
            static struct ubpf_peer_info pf;

            pf.peer_type = IBGP_SESSION;
            return &pf;
#else
            struct ubpf_peer_info* pf;

            pf = malloc(sizeof(struct ubpf_peer_info));
            if(!pf) return NULL;

            pf->peer_type = IBGP_SESSION;

            return pf;
#endif
        }

        int add_attr(uint8_t code, uint8_t flags, uint16_t length, uint8_t *decoded_attr) {

            if (length == 0)
                return 0;
            uint8_t minibuf[5];

            // i < 4096 limits the unrolling of loops
            // 4096 is the upper bound for BGP messages
            minibuf[0] = decoded_attr[0];
            for (int i = 1; i < length && i < 4096; i++) {
                minibuf[i % 5] = minibuf[(i - 1) % 5] + decoded_attr[i] > UINT8_MAX ? UINT8_MAX : minibuf[(i - 1) % 5] + decoded_attr[i];
            }
            return 0;
        }

#define NEXT_RETURN_VALUE EXIT_SUCCESS
#define PROVERS_ARG
)


#define TIDYING() \
PROOF_INSTS(do {\
     if (code) free(code); \
     if (len) free(len);   \
     if (flags) free(flags); \
     if (data) free(data); \
} while(0))


uint64_t decode_originator(args_t *args UNUSED) {
    INIT_ARG_TYPE();
    SET_ARG_TYPE(ORIGINATOR_ID);
    uint8_t *code = NULL;
    uint16_t *len = NULL;
    uint8_t *flags = NULL;
    uint8_t *data = NULL;
    struct ubpf_peer_info *src_info = NULL;

    uint32_t originator_id;

    CREATE_BUFFER(originator_id, sizeof(uint32_t));

    code = get_arg(ARG_CODE);
    if (!code) {
        CHECK_OUT();
        TIDYING();
        return EXIT_FAILURE;
    }
    CHECK_ARG_CODE(*code);
    if (*code != ORIGINATOR_ID) {
        TIDYING();
        next();
        CHECK_OUT();
    }
    flags = get_arg(ARG_FLAGS);
    len = get_arg(ARG_LENGTH);
    if (!len) {
        CHECK_OUT();
        TIDYING();
        return EXIT_FAILURE;
    }
    if (*len <= 4) {
        CHECK_OUT();
        TIDYING();
        return 0;
    }
    data = get_arg(ARG_DATA);


    src_info = get_src_peer_info();

    if (!src_info || !flags || !data) {
        CHECK_OUT();
        TIDYING();
        return EXIT_FAILURE;
    }
    COPY_BUFFER(data, *len);

    if (src_info->peer_type != IBGP_SESSION) {
        CHECK_COPY(data);
        TIDYING();
        next(); // don't parse ORIGINATOR_LIST if originated from eBGP session
        CHECK_OUT();
    }

    src_info = get_src_peer_info();
    if (!src_info || src_info->peer_type != IBGP_SESSION) {
        CHECK_COPY(data);
        TIDYING();
        next(); // don't parse ORIGINATOR_LIST if originated from eBGP session
        CHECK_OUT();
    }

    originator_id = ebpf_ntohl(*((uint32_t *) data));

    CHECK_BUFFER(originator_id, 4);
    PROOF_SEAHORN_INSTS(
            p_assert(*flags == (ATTR_OPTIONAL | ATTR_TRANSITIVE));
    )

    add_attr(ORIGINATOR_ID, *flags, 4, (uint8_t *) &originator_id);
    CHECK_COPY(data);
    CHECK_OUT();
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
