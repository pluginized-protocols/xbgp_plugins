//
// Created by thomas on 3/04/22.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../prove_stuffs/prove.h"

uint64_t encode_communities(args_t *args __attribute__((unused)));

PROOF_INSTS(
#define PROVERS_ARG
#define NEXT_RETURN_VALUE FAIL

        uint8_t nondet_u8(void);
        uint16_t nondet_u16(void);

        struct path_attribute *get_attr() {
            struct path_attribute *p_attr;
            uint16_t len = nondet_u16();
            p_attr = malloc(sizeof(*p_attr) + len);
            if (!p_attr) return NULL;

            p_attr->code = nondet_u8();
            p_attr->flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;
            p_attr->length = len;

            return p_attr;
        }
        )

#define TIDYING() \
PROOF_INSTS(do {            \
if (attribute) free(attribute); \
if (attr_buf) free(attr_buf); \
} while(0))

uint64_t encode_bgp_communities(args_t *args UNUSED) {
    INIT_ARG_TYPE();
    SET_ARG_TYPE(COMMUNITY_ATTR_ID);
    uint32_t counter = 0;
    uint8_t *attr_buf = NULL;
    uint16_t tot_len = 0;
    uint32_t *communities;
    unsigned int i;

    struct path_attribute *attribute;
    attribute = get_attr();
    CHECK_ARG(attribute);

    if (!attribute) {
        TIDYING();
        next();
        CHECK_OUT();
        return 0;
    }

    if (attribute->code != COMMUNITY_ATTR_ID) {
        TIDYING();
        next();
        CHECK_OUT();
        return 0;
    }

    tot_len += 2; // Type hdr
    tot_len += attribute->length < 256 ? 1 : 2; // Length hdr
    tot_len += attribute->length > UINT16_MAX-tot_len ? UINT16_MAX-tot_len : attribute->length;

    attr_buf = ctx_malloc(tot_len);
    CREATE_BUFFER(attr_buf, tot_len);
    if (!attr_buf) {
        CHECK_OUT();
        TIDYING();
        return 0;
    }

    attr_buf[counter++] = attribute->flags;
    attr_buf[counter++] = attribute->code;

    if (attribute->length < 256) attr_buf[counter++] = (uint8_t) attribute->length;
    else {
        memcpy(attr_buf+counter, &(attribute->length), 2);
        counter += 2;
    }

    communities = (uint32_t *) attribute->data;
    for (i = 0; i < attribute->length / 4 && i < 1024; i++) {
        *((uint32_t *) (attr_buf + counter)) = communities[i];
        counter += 4;
    }

    if (counter != tot_len) {
        ebpf_print("Size mismatch\n");
        CHECK_OUT();
        TIDYING();
        return 0;
    }

    CHECK_BUFFER(attr_buf, counter);
    PROOF_SEAHORN_INSTS(
            CHECK_ATTR(attr_buf);
            )
        if (write_to_buffer(attr_buf, counter) == -1)
        {
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
            uint64_t ret_val = encode_communities(&args);

            p_assert(ret_val >= 0 || ret_val == NEXT_RETURN_VALUE);

            return 0;
        }
        )