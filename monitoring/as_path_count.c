//
// Created by thomas on 12/02/21.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../prove_stuffs/prove.h"
#include "../prove_stuffs/prove_helpers.h"


#include <string.h>

#define max_bgp_msg UINT16_MAX

/* (min =  2 bytes for header + 4 bytes one AS) */
#define MIN_SEGMENT_SIZE 6

/* starting point */
uint64_t as_path_count(args_t *args UNUSED);

PROOF_INSTS(
#define NEXT_RETURN_VALUE EXIT_FAILURE
#define PROVERS_ARG
        uint16_t nondet_u16(void);
        uint8_t nondet_u8(void);

        static uint16_t length_attr = 0;

        void *get_arg(unsigned int id) {
            unsigned int attr_len;
            unsigned int *length;
            unsigned int *code;
            unsigned char *buf;

            switch (id) {
                case ARG_LENGTH:
                    if (!length) return NULL;
                    length_attr = nondet_u16(); // to be aligned with the buffer returned in arg_data

                    if (length_attr > 4096) return NULL;
                    if (length_attr < 2) return NULL;

                    length = malloc(sizeof(*length));
                    *length = length_attr;
                    return length;
                case ARG_CODE:
                    code = malloc(sizeof(*code));
                    if (!code) return NULL;
                    *code = nondet_u8();
                    return code;
                case ARG_DATA:
                    if (length_attr == 0) return NULL;
                    buf = malloc(length_attr);
                    if (!buf) return NULL;
                    return buf;
                default:
                    return NULL;
            }
        }
)


unsigned int __always_inline count_nb_as(const unsigned char *const as_path, unsigned int max_len) {
    unsigned int i = 0;
    unsigned char segment_length;
    unsigned int nb_as = 0;
    unsigned int tmp;

    if (max_len > max_bgp_msg) return UINT32_MAX;
    if (max_len < MIN_SEGMENT_SIZE) return UINT32_MAX; /*1771bis 4.3b: seg length contains one or more AS */

    if (max_len % 2) return UINT32_MAX;

    unsigned int j = 0; // dummy variable that helps T2 to prove the termination

    while (i < max_len && j < max_len) {
        if (max_len - i <= 2) return UINT32_MAX;

        // if the as_path buffer contains erroneous data,
        // "j" helps to prevent infinite loop by incrementing
        // j by MIN_SEGMENT_SIZE, by eventually leaving the loop
        j += MIN_SEGMENT_SIZE;

        segment_length = as_path[i + 1];
        nb_as += segment_length;

        tmp = (segment_length * 4) + 2;

        if ((((tmp + i) > max_len)
             || (segment_length <= 0)) != 0)
            return UINT32_MAX;

        i += tmp;
    }

    return nb_as;
}


#define TIDYING() \
PROOF_INSTS( do { \
    if (attribute_code) free(attribute_code); \
    if (as_path_len) free(as_path_len);                \
    if (as_path) free(as_path); \
} while(0))

uint64_t as_path_count(args_t *args UNUSED) {
    INIT_ARG_TYPE();
    SET_ARG_TYPE(AS_PATH_ATTR_ID);
    unsigned int as_number = 0;
    unsigned int *attribute_code = get_arg(ARG_CODE);
    CHECK_ARG_CODE(*attribute_code);
    unsigned int *as_path_len = get_arg(ARG_LENGTH);
    unsigned char *as_path = get_arg(ARG_DATA);

    if (!as_path || !as_path_len || !attribute_code) {
        // unable to fetch data from host implementation
        TIDYING();
        return EXIT_FAILURE;
    }

    COPY_BUFFER(as_path, *as_path_len);
    if (*attribute_code != AS_PATH_ATTR_ID) {
        CHECK_COPY(as_path);
        TIDYING();
        next();
        CHECK_OUT();
        return EXIT_FAILURE;
    }

    // core part of the plugin
    as_number = count_nb_as(as_path, *as_path_len);

    if (as_number == UINT32_MAX) {
        CHECK_COPY(as_path);
        TIDYING();
        CHECK_OUT();
        return EXIT_FAILURE;
    }

    // log the message. If it fails, returns error code
    if (log_msg(L_INFO "as_count:%d\n", LOG_UINT(as_number)) != 0) {
        CHECK_COPY(as_path);
        TIDYING();
        CHECK_OUT();
        return EXIT_FAILURE;
    }
    CHECK_COPY(as_path);
    TIDYING();
    CHECK_OUT();
    return EXIT_SUCCESS;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret = as_path_count(&args);
            p_assert(ret == EXIT_FAILURE || ret == EXIT_SUCCESS);
            return 0;
        }
)