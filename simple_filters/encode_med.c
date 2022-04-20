//
// Created by thomas on 9/04/22.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "med_hdr.h"
#include "../prove_stuffs/prove.h"


uint64_t encode_med(args_t *args __attribute__((unused)));

PROOF_INSTS(
#define NEXT_RETURN_VALUE EXIT_SUCCESS

        uint8_t nondet_u8();
        uint16_t nondet_u16();

        struct path_attribute *get_attr() {
            struct path_attribute *p_attr;
            uint16_t len = nondet_u16();
            p_attr = malloc(sizeof(*p_attr) + len);
            if (!p_attr) return NULL;

            p_attr->code = nondet_u8();
            p_attr->flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;
            p_attr->length = len;
            for (int i = 0 ; i < len ; i++)
                p_attr->data[i] = nondet_u8();

            return p_attr;
        }
        )

#define TIDYING() \
PROOF_INSTS(do {            \
    if (attribute) free(attribute); \
} while(0))

uint64_t encode_med(args_t *args UNUSED) {
    INIT_ARG_TYPE();
    SET_ARG_TYPE(MULTI_EXIT_DISC_ATTR_ID);
    unsigned int counter;
    uint8_t attr_buf[TOTAL_LENGTH_ENCODED_MED_ATTR];
    CREATE_BUFFER(attr_buf, TOTAL_LENGTH_ENCODED_MED_ATTR);
    struct path_attribute *attribute;

    attribute = get_attr();
    counter = 0;

    if (!attribute) {
        TIDYING();
        next();
        CHECK_OUT();
        return 0;
    }

    if (attribute->code != MULTI_EXIT_DISC_ATTR_ID || attribute->length != LENGTH_MED_VALUE) {
        TIDYING();
        next();
        CHECK_OUT();
        return 0;
    }

    attr_buf[counter++] = attribute->flags;
    attr_buf[counter++] = attribute->code;
    attr_buf[counter++] = LENGTH_MED_VALUE;

    memcpy(attr_buf + counter, attribute->data, LENGTH_MED_VALUE);
    counter += 4;

    CHECK_BUFFER(attr_buf, counter);
    BUF_CHECK_ATTR_FORMAT(attr_buf, counter);
    if (write_to_buffer(attr_buf, counter) == -1) return 0;

    if (counter != TOTAL_LENGTH_ENCODED_MED_ATTR) {
        ebpf_print("[ERROR] ATTR MED SIZE MISSMATCH !\n");
        CHECK_OUT();
        TIDYING();
        return 0;
    }

    CHECK_OUT();
    TIDYING();
    return counter;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = encode_med(&args);

            return 0;
        }
        )