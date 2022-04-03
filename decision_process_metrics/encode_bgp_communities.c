//
// Created by thomas on 3/04/22.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"

uint64_t encode_communities(args_t *args __attribute__((unused)));

uint64_t encode_communities(args_t *args UNUSED) {
    uint32_t counter = 0;
    uint8_t *attr_buf = NULL;
    uint16_t tot_len = 0;
    uint32_t *communities;
    unsigned int i;

    struct path_attribute *attribute;
    attribute = get_attr();

    if (!attribute) {
        next();
        return 0;
    }

    if (attribute->code != COMMUNITY_ATTR_ID) {
        next();
        return 0;
    }

    tot_len += 2; // Type hdr
    tot_len += attribute->length < 256 ? 1 : 2; // Length hdr
    tot_len += attribute->length;

    attr_buf = ctx_malloc(tot_len);
    if (!attr_buf) {
        return 0;
    }

    attr_buf[counter++] = attribute->flags;
    attr_buf[counter++] = attribute->code;

    if (attribute->length < 256) attr_buf[counter++] = (uint8_t) attribute->length;
    else {
        *(uint16_t *)(attr_buf + counter) = attribute->length;
        counter += 2;
    }

    communities = (uint32_t *) attribute->data;
    for (i = 0; i < attribute->length / 4 && i < 1024; i++) {
        *((uint32_t *) (attr_buf + counter)) = communities[i];
        counter += 4;
    }

    if (counter != tot_len) {
        ebpf_print("Size mismatch\n");
        return 0;
    }

    if (write_to_buffer(attr_buf, counter) == -1) return 0;
    return counter;
}
