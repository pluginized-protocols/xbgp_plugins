//
// Created by thomas on 29/01/21.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../xbgp_compliant_api/xbgp_defs.h"
#include "../prove_stuffs/prove.h"

PROOF_INSTS(
        uint8_t nondet_u8(void);
        void *get_arg(unsigned int arg_type) {
            if (arg_type != ARG_CODE) return NULL;

            uint8_t *the_code;
            the_code = malloc(sizeof(*the_code));
            if (!the_code) return NULL;

            *the_code = nondet_u8();
            return the_code;
        }

)

#define TIDYING() \
PROOF_INSTS( do { \
    if (code) free(code);\
}while(0);)


/* starting point */
uint64_t reject_route_attr_42(args_t *args UNUSED);

uint64_t reject_route_attr_42(args_t *args UNUSED) {

    uint8_t *code;
    code = get_arg(ARG_CODE);

    if (!code) {
        ebpf_print("There was an error\n");
        TIDYING();
        return PLUGIN_FILTER_UNKNOWN;
    }

    if (*code == 42) {
        ebpf_print("The update is rejected since it contains the attribute 42\n");
        TIDYING();
        return PLUGIN_FILTER_REJECT;
    }

    // ebpf_print("Update accepted\n");
    TIDYING();
    return PLUGIN_FILTER_ACCEPT;

}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret;

            ret = reject_route_attr_42(&args);

            PROOF_SEAHORN_INSTS(
                    RET_VAL_FILTERS_CHECK(ret);
            )

            return 0;

        }
)