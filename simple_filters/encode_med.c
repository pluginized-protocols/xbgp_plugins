//
// Created by thomas on 9/04/22.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "med_hdr.h"


uint64_t encode_med(args_t *args __attribute__((unused)));

uint64_t encode_med(args_t *args UNUSED) {
    unsigned int counter;
    uint8_t attr_buf[TOTAL_LENGTH_ENCODED_MED_ATTR];
    struct path_attribute *attribute;

    attribute = get_attr();
    counter = 0;

    if (!attribute) {
        next();
        return 0;
    }

    if (attribute->code != MULTI_EXIT_DISC_ATTR_ID) {
        next();
        return 0;
    }

    attr_buf[counter++] = attribute->flags;
    attr_buf[counter++] = attribute->code;
    attr_buf[counter++] = LENGTH_MED_VALUE;

    memcpy(attr_buf + counter, attribute->data, LENGTH_MED_VALUE);
    counter += 4;

    if (write_to_buffer(attr_buf, counter) == -1) return 0;

    if (counter != TOTAL_LENGTH_ENCODED_MED_ATTR) {
        ebpf_print("[ERROR] ATTR MED SIZE MISSMATCH !\n");
        return 0;
    }

    return counter;
}