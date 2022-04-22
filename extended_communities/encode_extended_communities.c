//
// Created by thomas on 20/05/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_ext_comm.h"

uint64_t encode_extended_communities(args_t *args __attribute__((unused)));

#include "../prove_stuffs/prove.h"


PROOF_INSTS(
        struct path_attribute *get_attr(void);

        uint16_t nondet_u16(void);

        struct path_attribute *get_attr() {
            uint16_t len;
            struct path_attribute *p_attr;
            len = nondet_u16();
            p_attr = malloc(sizeof(*p_attr) + len);

            if (p_attr == NULL) return NULL;

            p_attr->flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;
            p_attr->code = EXTENDED_COMMUNITIES_ATTR_ID;
            p_attr->length = len;

            return p_attr;
        }
#define NEXT_RETURN_VALUE 0
)

#define TIDYING() \
PROOF_INSTS(do {            \
    if (attribute) free(attribute); \
    if (attr_buf)  free(attr_buf);\
} while(0))

uint64_t encode_extended_communities(args_t *args UNUSED) {
    uint32_t counter = 0;
    uint8_t *attr_buf = NULL;
    uint16_t tot_len = 0;
    uint64_t *ext_communities;
    unsigned int i;

    struct path_attribute *attribute;
    attribute = get_attr();

    if (!attribute) {
        next();
        return 0;
    }

    if (attribute->code != EXTENDED_COMMUNITIES) {
        TIDYING();
        next();
        return 0;
    }

    if (attribute->length < 8 || attribute->length % 8 != 0) {
        TIDYING();
        return 0; // min length extended communities is 8 bytes || malformed attribute (extcomm must be a multiple of 8)
    }

    tot_len += 2; // Type hdr
    tot_len += attribute->length < 256 ? 1 : 2; // Length hdr
    tot_len += attribute->length;

    attr_buf = ctx_calloc(1, tot_len);
    if (!attr_buf) {
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

    ext_communities = (uint64_t *) attribute->data;
    //assume(attribute->length <= 4096u);
    for (i = 0; i < attribute->length / 8 && i < 512; i++) {
        *((uint64_t *) (attr_buf + counter)) = ebpf_htonll(ext_communities[i]);
        counter += 8;
    }

    if (counter != tot_len) {
        ebpf_print("Size mismatch\n");
        TIDYING();
        return 0;
    }

    PROOF_SEAHORN_INSTS(
            BUF_CHECK_EXTENDED_COMMUNITY(attr_buf, attribute->length);
    )

    if (write_to_buffer(attr_buf, counter) == -1) return 0;

    TIDYING();
    return counter;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = encode_extended_communities(&args);
            return ret_val;
        }
)