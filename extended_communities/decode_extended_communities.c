//
// Created by thomas on 20/05/20.
//

#include <stdint.h>
#include <bytecode_public.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_ext_comm.h"

#include "../prove_stuffs/prove.h"

/* starting point */
uint64_t decode_extended_communities(args_t *args UNUSED);


PROOF_INSTS(
        uint16_t get_length();

        void *get_arg(unsigned int id) {

            int nb_extended = 10;

            switch (id) {
                case ARG_CODE: {
                    uint8_t *code = malloc(sizeof(uint8_t));
                    if (!code) return NULL;

                    *code = EXTENDED_COMMUNITIES;
                    return code;
                }
                case ARG_DATA: {
                    uint64_t *ec = malloc(sizeof(uint64_t) * nb_extended);
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

                    *length = get_length();

                    return length;
                }
                default:
                    return NULL;
            }
        }
#define NEXT_RETURN_VALUE EXIT_FAILURE
)


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

    //assume(*flags == (ATTR_OPTIONAL | ATTR_TRANSITIVE));

    in_ext_communitites = (uint64_t *) data;

    decoded_ext_communitities = ctx_malloc(*len);
    if (!decoded_ext_communitities) next();

    for (i = 0; i < *len / 8; i++) {
        decoded_ext_communitities[i] = ebpf_ntohll(in_ext_communitites[i]);
    }

    p_assert(*len % 8 == 0);
    p_assert(*flags == (ATTR_OPTIONAL | ATTR_TRANSITIVE));

    add_attr(EXTENDED_COMMUNITIES, *flags, *len, (uint8_t *) decoded_ext_communitities);

    return EXIT_SUCCESS;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = decode_extended_communities(&args);
            return ret_val;
        }
)