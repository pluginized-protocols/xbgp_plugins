//
// Created by thomas on 29/01/21.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../xbgp_compliant_api/xbgp_defs.h"

/* starting point */
uint64_t filter_attr_42(args_t *args UNUSED);

uint64_t filter_attr_42(args_t *args UNUSED) {

    uint8_t *code;
    code = get_arg(ARG_CODE);

    if (!code) {
        ebpf_print("There was an error\n");
        return EXIT_FAILURE;
    }

    if (*code == 42) {
        ebpf_print("The update is rejected since it contains the attribute 42\n");
        return PLUGIN_FILTER_REJECT;
    }

    ebpf_print("Update accepted\n");
    return PLUGIN_FILTER_ACCEPT;

}