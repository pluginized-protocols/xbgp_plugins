//
// Created by thomas on 11/02/22.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "propagation_time_common.h"
#include "../prove_stuffs/prove.h"

/* entry point */
uint64_t decode_arrival_attr(args_t *args UNUSED);

PROOF_INSTS(
#define NEXT_RETURN_VALUE FAIL
        uint8_t nondet_u8(void);
        uint16_t nondet_u16(void);

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
                        data_length = nondet_u16();
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
        )

#define TIDYING() \
PROOF_INSTS(do {            \
if (code) free(code); \
if (len) free(len); \
if (flags) free(flags); \
if (data) free(data); \
if (src_info) free(src_info); \
} while(0);)

uint64_t decode_arrival_attr(args_t *args UNUSED) {
    struct ubpf_peer_info *src_info = NULL;
    char attr_space[sizeof(struct path_attribute) + sizeof(struct attr_arrival)];
    struct path_attribute *attr;
    struct attr_arrival *arrival;

    uint8_t *code = NULL;
    uint16_t *len = NULL;
    uint8_t *flags = NULL;
    uint8_t *data = NULL;

    code = get_arg(ARG_CODE);
    flags = get_arg(ARG_FLAGS);
    data = get_arg(ARG_DATA);
    len = get_arg(ARG_LENGTH);

    src_info = get_src_peer_info();

    if (!src_info || !code || !len || !flags || !data) {
        TIDYING();
        return EXIT_FAILURE;
    }

    if (src_info->peer_type != IBGP_SESSION) {
        next();
    }

    if (*code != ARRIVAL_TIME_ATTR) {
        next();
    }

    attr = (struct path_attribute *) attr_space;
    arrival = (struct attr_arrival *) attr->data;

    /* read seconds */
    arrival->arrival_time.tv_sec = read_u64(data);
    /* read nanosecs */
    arrival->arrival_time.tv_nsec = read_u64(data);
    /* read origin AS */
    arrival->from_as = read_u32(data);


    if (set_attr(attr) != 0) return EXIT_FAILURE;
    TIDYING();
    return EXIT_SUCCESS;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = decode_arrival_attr(&args);

            p_assert(ret_val == EXIT_SUCCESS ||
            ret_val == EXIT_FAILURE);

            ctx_shmrm(42);

            return 0;
        }
        )