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

        void nondet_set_data__verif(void *data);

        struct path_attribute *get_attr() {

            struct path_attribute *p_attr;
            p_attr = malloc(sizeof(*p_attr) + 64);

            if (p_attr == NULL) return NULL;

            p_attr->flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;
            p_attr->code = EXTENDED_COMMUNITIES_ATTR_ID;
            p_attr->length = 64;
            nondet_set_data__verif(p_attr->data);

            return p_attr;
        }
#define NEXT_RETURN_VALUE 0
)


uint64_t encode_extended_communities(args_t *args UNUSED) {

    uint32_t counter = 0;
    uint8_t *attr_buf;
    uint16_t tot_len = 0;
    uint64_t *ext_communities;
    int i;

    struct path_attribute *attribute;
    attribute = get_attr();

    if (!attribute) return 0;

    if (attribute->code != EXTENDED_COMMUNITIES) next();

    tot_len += 2; // Type hdr
    tot_len += attribute->length < 256 ? 1 : 2; // Length hdr
    tot_len += attribute->length;

    attr_buf = ctx_calloc(1, tot_len);
    if (!attr_buf) return 0;

    attr_buf[counter++] = attribute->flags;
    attr_buf[counter++] = attribute->code;

    if (attribute->length < 256) attr_buf[counter++] = (uint8_t) attribute->length;
    else {
        attr_buf[counter] = attribute->length;
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
        return 0;
    }

    PROOF_SEAHORN_INSTS(
            BUF_CHECK_EXTENDED_COMMUNITY(attr_buf, attribute->length);
    )

    if (write_to_buffer(attr_buf, counter) == -1) return 0;

    //ctx_free(attr_buf);
    return counter;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = decode_extended_communities(&args);
            return ret_val;
        }
)