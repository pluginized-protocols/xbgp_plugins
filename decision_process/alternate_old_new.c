//
// Created by thomas on 20/07/21.
//
#include "../xbgp_compliant_api/xbgp_plugin_api.h"

void *memset(void *s, int c, size_t n);

#define str_equal(str1, str2, maxlen) ({            \
    int i__;                                        \
    int ret__ = 0;                                  \
    const char *str1__ = (str1);                    \
    const char *str2__ = (str2);                    \
    if ((maxlen) == 0) ret__ = 1;                   \
    for (i__ = 0; i__ < (maxlen); i__++) {          \
        if (*(str1__) != *(str2__++)) {             \
            ret__ = 0;                              \
            break;                                  \
        } else if (*(str1__++) == 0) {              \
            ret__ = 1;                              \
            break;                                  \
        }                                           \
    }                                               \
    ret__;                                          \
})


/**
 * Simple decision to verify that we can
 * influence the decision process of a
 * single client running in its own VRF.
 *
 * @return BGP_ROUTE_TYPE_OLD to keep the old best route
 *         BGP_ROUTE_TYPE_NEW to change the best route
 */
uint64_t dumb_decision(args)
        args_t *args UNUSED;
{
    int *choice;
    struct vrf_info info;
    int decision;

    memset(&info, 0, sizeof(info));
    if (get_vrf(&info) != 0) {
        log_msg(L_INFO"Unable to get VRF !");
        return BGP_ROUTE_TYPE_FAIL;
    }

    if (!str_equal(info.name, "red", 3)) {
        return BGP_ROUTE_TYPE_FAIL;
    }

    /* just load balance between old and new
     * before as-path check !
     * We remember the previous choice by
     * storing it to a shared memory that
     * persists across two VM calls
     */
    choice = ctx_shmget(42);
    if (choice == NULL) {
        choice = ctx_shmnew(42, sizeof(*choice));
        if (!choice) return BGP_ROUTE_TYPE_FAIL;
        *choice = 0;
    }
    decision = *choice;
    *choice = (*choice + 1) % 2;

    switch (decision) {
        case 0:
            return BGP_ROUTE_TYPE_NEW;
        case 1:
            return BGP_ROUTE_TYPE_OLD;
        default:
            return BGP_ROUTE_TYPE_FAIL;
    }
}