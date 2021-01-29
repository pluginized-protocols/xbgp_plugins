//
// Created by thomas on 29/01/21.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../xbgp_compliant_api/xbgp_defs.h"
#include <bytecode_public.h>


uint64_t filter_attr_42(args_t *args UNUSED) {

    int *code;
    code = get_arg(0); // todo change

    if (!code) {
        return EXIT_FAILURE;
    }

    return *code == 42 ? EXIT_FAILURE : EXIT_SUCCESS;

}