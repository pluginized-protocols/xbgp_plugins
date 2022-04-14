//
// Created by thomas on 11/02/22.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "propagation_time_common.h"
#include "../prove_stuffs/prove.h"

/* entry point */
uint64_t decode_arrival_attr(args_t *args UNUSED);

PROOF_INSTS(
#define PROVERS_ARG
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
                    if (data_length == 0) {
                        data_length = nondet_u16();
                        p_assume(data_length > 0);
                    }
                    uint8_t *data = malloc(data_length);
                    for (int i = 0 ; i < data_length ; i++)
                        data[i] = nondet_u8();
                    return data;
                }
                case ARG_LENGTH: {
                    uint16_t *length;
                    if (data_length == 0) {
                        data_length = nondet_u16();
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
    INIT_ARG_TYPE();
    SET_ARG_TYPE(ARRIVAL_TIME_ATTR);
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
    len = get_arg(ARG_LENGTH);
    data = get_arg(ARG_DATA);

    src_info = get_src_peer_info();

    if (!src_info || !code || !len || !flags || !data) {
        CHECK_OUT();
        TIDYING();
        return EXIT_FAILURE;
    }
    CHECK_ARG_CODE(*code);

    if (src_info->peer_type != IBGP_SESSION) {
        TIDYING();
        next();
        CHECK_OUT();
    }

    if (*code != ARRIVAL_TIME_ATTR) {
        TIDYING();
        next();
        CHECK_OUT();
    }

    if (*len < ARRIVAL_TIME_ATTR_LEN) {
        CHECK_OUT();
        TIDYING();
        return EXIT_FAILURE;
    }

    attr = (struct path_attribute *) attr_space;
    attr->code = ARRIVAL_TIME_ATTR;
    attr->flags = 0;
    attr->length = sizeof(struct attr_arrival);
    arrival = (struct attr_arrival *) attr->data;

    /* read seconds */
    uint64_t t = read_u64(data);
    arrival->arrival_time.tv_sec = t > INT64_MAX ? INT64_MAX : t;
    /* read nanosecs */
    t = read_u64(data);
    arrival->arrival_time.tv_nsec = t > INT64_MAX ? INT64_MAX : t;
    /* read origin AS */
    arrival->from_as = read_u32(data);

    PROOF_SEAHORN_INSTS(
            CHECK_ATTR_FORMAT(attr, ARRIVAL_TIME_ATTR_LEN);
    )

    if (set_attr(attr) != 0){
        CHECK_OUT();
        TIDYING();
        return EXIT_FAILURE;
    }
    CHECK_OUT();
    TIDYING();
    return EXIT_SUCCESS;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = decode_arrival_attr(&args);

            p_assert(ret_val == EXIT_SUCCESS ||
            ret_val == EXIT_FAILURE);


            return 0;
        }
        )