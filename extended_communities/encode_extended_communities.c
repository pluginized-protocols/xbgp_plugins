//
// Created by thomas on 20/05/20.
//

#include "../../public_bpf.h"
#include "ubpf_api.h"
#include "common_ext_comm.h"

uint64_t generic_encode_attr(bpf_full_args_t *args __attribute__((unused))) {

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
    tot_len += attribute->len < 256 ? 1 : 2; // Length hdr
    tot_len += attribute->len;

    attr_buf = ctx_calloc(1, tot_len);
    if (!attr_buf) return 0;

    attr_buf[counter++] = attribute->flags;
    attr_buf[counter++] = attribute->code;

    if (attribute->len < 256) attr_buf[counter++] = (uint8_t) attribute->len;
    else {
        attr_buf[counter] = attribute->len;
        counter += 2;
    }

    ext_communities = (uint64_t *) attribute->data;
    for (i = 0;  i < attribute->len/8; i++) {
        *((uint64_t *)(attr_buf + counter)) = ebpf_htonll(ext_communities[i]);
        counter += 8;
    }

    if(counter != tot_len) {
        ebpf_print("Size missmatch\n");
        return 0;
    }

    if (write_to_buffer(attr_buf, counter) == -1) return 0;
    return counter;
}