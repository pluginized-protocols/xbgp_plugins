//
// Created by thomas on 9/04/22.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "med_hdr.h"
#include "../prove_stuffs/prove.h"

uint64_t set_med_42(void);

PROOF_INSTS(
#define NEXT_RETURN_VALUE EXIT_SUCCESS
        )

/**
 * Simple import filter that adds the
 * med value for each route
 */
uint64_t set_med_42(void) {
    uint32_t med_val;
    char buf[sizeof(struct path_attribute) + sizeof(LENGTH_MED_VALUE)];
    struct path_attribute *p_attr;

    med_val = ebpf_htonl(MED_HARD_VAL);
    p_attr = (struct path_attribute *) buf;

    p_attr->code = MULTI_EXIT_DISC_ATTR_ID;
    p_attr->flags = ATTR_OPTIONAL;
    p_attr->length = LENGTH_MED_VALUE;
    memcpy(p_attr->data, &med_val, sizeof(LENGTH_MED_VALUE));

    CHECK_ATTR_FORMAT(p_attr, sizeof(struct path_attribute) + sizeof(LENGTH_MED_VALUE));
    if (set_attr(p_attr) != 0) {
        ebpf_print("[WARN] Unable to set MED value !\n");
    }
    // this plugin does not decide anything
    next();
    return PLUGIN_FILTER_UNKNOWN;
}

PROOF_INSTS(
        int main(void) {
            uint64_t ret_val = set_med_42();

            return 0;
        }
        )