//
// Created by thomas on 29/01/21.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../xbgp_compliant_api/xbgp_defs.h"
#include <bytecode_public.h>


uint64_t filter_attr_42(args_t *args) {

    int *code;
    ret = get_arg(BGP_ATTR_CODE);

    if (!ret) {
        return EXIT_FAILURE;
    }

    return *code == 42 ? EXIT_FAILURE : EXIT_SUCCESS;

}