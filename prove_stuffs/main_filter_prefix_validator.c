//
// Created by thomas on 26/03/21.
//

#include <string.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include <assert.h>


uint64_t prefix_validator(args_t *args UNUSED);

int main(void) {
    args_t args;
    uint64_t ret_val;

    memset(&args, 0, sizeof(args));
    ret_val = prefix_validator(&args);

    assert(ret_val == EXIT_FAILURE || ret_val == EXIT_SUCCESS);
    return EXIT_SUCCESS;
}