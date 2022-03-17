#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../byte_manip.h" // get_u32 macro definition

#include "../prove_stuffs/prove.h"

#define AS_PATH_ATTR_ID 2

#define MIN_ASPATH_LEN 4

PROOF_INSTS(
        uint16_t nondet_len();

        struct path_attribute *get_attr_from_code(uint8_t code) {
            struct path_attribute *obj;
            uint16_t len = nondet_len();
            if (len > 4096 || len < MIN_ASPATH_LEN) return NULL;
            obj = malloc(sizeof(struct path_attribute) + len);
            if (obj == NULL) return NULL;
            obj->length = len;
            return obj;
        }
)

/* starting point */
uint64_t filter_odd_as(args_t *args UNUSED);

#define TIDYING() \
PROOF_INSTS(do {            \
    if (as_path) free(as_path); \
} while(0);)


uint64_t filter_odd_as(args_t *args UNUSED) {

    unsigned int i, j;
    struct path_attribute *as_path;
    uint8_t *as_path_data;
    uint8_t segment_length;

    uint32_t asn;

    as_path = get_attr_from_code(AS_PATH_ATTR_ID);
    if (as_path == NULL) return PLUGIN_FILTER_UNKNOWN;

    if (as_path->length <= 0) {
        TIDYING();
        return PLUGIN_FILTER_UNKNOWN;
    }

    as_path_data = as_path->data;

    i = 0;
    while (i < as_path->length && i >= 0) {
        if (as_path->length - i <= 2) {
            TIDYING();
            return PLUGIN_FILTER_UNKNOWN;
        }

        i++; // skip segment type
        segment_length = as_path_data[i++];

        for (j = 0; j < segment_length && segment_length > 0; j++) {
            if (as_path->length - i <= 4) {
                TIDYING();
                return PLUGIN_FILTER_UNKNOWN;
            }
            uint32_t o = *(uint32_t *) (as_path_data + i);
            asn = get_u32_t2_friendly(o);
            i += 4;
        }
    }

    if (asn % 2 == 0) {
        TIDYING();
        return PLUGIN_FILTER_ACCEPT;
    }

    TIDYING();
    return PLUGIN_FILTER_REJECT;
}

PROOF_INSTS(
        int main(void) {
            uint64_t ret;
            args_t args = {};
            ret = filter_odd_as(&args);

            PROOF_SEAHORN_INSTS(
                    RET_VAL_FILTERS_CHECK(ret);
            )

            return ret;
        }
)