//
// Created by thomas on 18/03/21.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include <assert.h>

extern uint64_t add_prefix_originator(args_t *args UNUSED);

int main(void) {
    uint64_t ret_val;
    args_t args;
    ret_val = 42;

    ret_val = add_prefix_originator(&args);
    assert(ret_val == PLUGIN_FILTER_REJECT || ret_val== PLUGIN_FILTER_ACCEPT || ret_val == PLUGIN_FILTER_UNKNOWN);

    return 0;
}