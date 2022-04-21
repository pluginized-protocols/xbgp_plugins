//
// Created by thomas on 20/05/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_ext_comm.h"

#include "../prove_stuffs/prove.h"
#include "../prove_stuffs/prove_helpers.h"

/* starting point */
uint64_t decode_extended_communities(args_t *args UNUSED);


PROOF_INSTS(
        uint16_t get_length(void);
        uint64_t nondet_uint64(void);
        uint8_t nondet_uint8(void);

        static uint16_t def_len = 0;

        void *get_arg(unsigned int id) {

            if (def_len == 0) {
                def_len = get_length();
            }

            switch (id) {
                case ARG_CODE: {
                    uint8_t *code = malloc(sizeof(uint8_t));
                    if (!code) return NULL;

                    *code = nondet_uint8();
                    return code;
                }
                case ARG_DATA: {
                    uint64_t *ec = malloc(sizeof(uint64_t) * def_len);
                    if (!ec) return NULL;

                    return ec;
                }
                case ARG_FLAGS: {
                    uint8_t *flags = malloc(sizeof(uint8_t));
                    if (!flags) return NULL;

                    *flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;

                    return flags;
                }
                case ARG_LENGTH: {
                    uint16_t *length = malloc(sizeof(uint16_t));
                    if (!length) return NULL;

                    *length = def_len;
                    return length;
                }
                default:
                    return NULL;
            }
        }
#define NEXT_RETURN_VALUE EXIT_FAILURE
)

#define PROVERS_SEAHORN
#define PROVERS
#define TIDYING() \
PROOF_INSTS(do {     \
    if (code) free(code); \
    if (len) free(len);   \
    if (flags) free(flags); \
    if (data) free(data);\
    if (decoded_ext_communitities) free(decoded_ext_communitities); \
} while(0))

uint64_t decode_extended_communities(args_t *args UNUSED) {

    int i;

    uint8_t *code = NULL;
    uint16_t *len = NULL;
    uint8_t *flags = NULL;
    uint8_t *data = NULL;

    uint64_t *in_ext_communitites;
    uint64_t *decoded_ext_communitities = NULL;

    code = get_arg(ARG_CODE);
    if (code != NULL && *code != EXTENDED_COMMUNITIES) {
        TIDYING();
        next();
    }
    flags = get_arg(ARG_FLAGS);
    len = get_arg(ARG_LENGTH);
    if (!len || *len % 8 != 0) {
        // malformed extended attribute
        TIDYING();
        return EXIT_FAILURE;
    }

    data = get_arg(ARG_DATA);

    if (!code || !flags || !data) {
        TIDYING();
        return EXIT_FAILURE;
    }
    COPY_BUFFER(data, *len);

    in_ext_communitites = (uint64_t *) data;

    decoded_ext_communitities = ctx_malloc(*len);

    CREATE_BUFFER(decoded_ext_communitities, *len);
    if (!decoded_ext_communitities) {
        CHECK_COPY(data);
        TIDYING();
        next();
    }

    for (i = 0; i < *len / 8 PROOF_T2_INSTS(&& i < 512); i++) {
        PROOF_SEAHORN_INSTS(in_ext_communitites[i] = nondet_uint64();)
        decoded_ext_communitities[i] = ebpf_ntohll(in_ext_communitites[i]);
    }

    CHECK_BUFFER(decoded_ext_communitities, *len);
    p_assert(*len % 8 == 0);
    p_assert(*flags == (ATTR_OPTIONAL | ATTR_TRANSITIVE));
    add_attr(EXTENDED_COMMUNITIES, *flags, *len, (uint8_t *)decoded_ext_communitities);
    CHECK_COPY(data);
    TIDYING();
    return EXIT_SUCCESS;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = decode_extended_communities(&args);
            return ret_val;
        }
        )