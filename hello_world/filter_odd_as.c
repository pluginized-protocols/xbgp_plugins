#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include <bytecode_public.h>
#include "../byte_manip.h" // get_u32 macro definition

#define AS_PATH_ATTR_ID 2

uint64_t filter_route_originated_from_odd_as(args_t *args UNUSED) {

    int i, j;
    struct path_attribute *as_path;
    uint8_t *as_path_data;
    uint8_t segment_length;

    uint32_t asn;

    as_path =  get_attr_from_code(AS_PATH_ATTR_ID);

    if (!as_path) return PLUGIN_FILTER_UNKNOWN;
    if (as_path->length <= 0) return PLUGIN_FILTER_UNKNOWN;

    as_path_data = as_path->data;

    i = 0;
    while (i < as_path->length && i >= 0) {
        if (as_path->length - i <= 2) return -1;

        i++; // skip segment type
        segment_length = as_path_data[i++];

        for (j = 0; j < segment_length  && segment_length > 0; j++) {
            unsigned long o = * (unsigned long *) (as_path_data + i);
            asn = get_u32_t2_friendly(o);
            if(as_path->length - i <= 4) return -1;
            i += 4;
        }
    }

    if (asn % 2 == 0) {
        return PLUGIN_FILTER_ACCEPT;
    }

    return PLUGIN_FILTER_REJECT;
}