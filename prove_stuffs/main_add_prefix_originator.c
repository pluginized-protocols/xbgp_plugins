//
// Created by thomas on 1/04/21.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "mod_ubpf_api.h"

extern uint64_t add_prefix_originator(args_t *args UNUSED);


int main(void) {

    uint64_t ret_val;
    args_t args = {};

    ret_val = add_prefix_originator(&args);

    return EXIT_SUCCESS;
}