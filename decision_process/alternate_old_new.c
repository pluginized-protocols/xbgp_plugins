//
// Created by thomas on 20/07/21.
//
#include "../xbgp_compliant_api/xbgp_plugin_api.h"

#include "../prove_stuffs/prove.h"


__always_inline int
strncmp(const char *s1, const char *s2, size_t n) {
    register unsigned char u1, u2;
    if (n == 0) return 0;
    while (n > 0) {
        u1 = (unsigned char) *s1++;
        u2 = (unsigned char) *s2++;
        if (u1 != u2)
            return u1 - u2;
        if (u1 == '\0')
            return 0;
        n -= 1;
    }
    return 0;
}

/* starting point */
uint64_t alternate_old_new(args_t *args UNUSED);

PROOF_INSTS(
#define NEXT_RETURN_VALUE BGP_ROUTE_TYPE_UNKNOWN
        int nondet_len(void);

        int get_vrf(struct vrf_info *vrf_info) {
            const char my_vrf[] = "red";
            if (!vrf_info) return -1;

            if (vrf_info->str_len >= sizeof(my_vrf)) {
                strncpy(vrf_info->name, my_vrf, sizeof(my_vrf));
            }
            vrf_info->vrf_id = nondet_len();
            return 0;
        }
)

void *memset(void *s, int c, size_t n);

struct stats {
    int choice;
    unsigned long long int counter;
};


/**
 * Simple decision to verify that we can
 * influence the decision process of a
 * single client running in its own VRF.
 *
 * @return BGP_ROUTE_TYPE_OLD to keep the old best route
 *         BGP_ROUTE_TYPE_NEW to change the best route
 */
uint64_t alternate_old_new(args_t *args UNUSED) {
    struct stats *st_sh;
    int decision;
    uint8_t buf[sizeof(struct vrf_info) + 50]; // space for struct + string on the stack
    memset(buf, 0, sizeof(buf));

    struct vrf_info *info = (struct vrf_info *) buf;
    info->str_len = 50;

    if (get_vrf(info) != 0) {
        log_msg(L_INFO"Unable to get VRF !");
        ebpf_print("Unable to get the vrf\n");
        return BGP_ROUTE_TYPE_FAIL;
    }

    if (strncmp(info->name, "red", 3) != 0) {
        next();
        return BGP_ROUTE_TYPE_FAIL;
    }

    /* just load balance between old and new
     * before as-path check !
     * We remember the previous choice by
     * storing it to a shared memory that
     * persists across two VM calls
     */
    st_sh = ctx_shmget(42);
    if (st_sh == NULL) {
        st_sh = ctx_shmnew(42, sizeof(*st_sh));
        if (!st_sh) {
            ebpf_print("Unable to create shared memory!");
            return BGP_ROUTE_TYPE_FAIL;
        }
        st_sh->choice = 0;
        st_sh->counter = 0;
    }
    decision = (st_sh->counter % 3) == 0;
    st_sh->choice = decision;
    st_sh->counter++;

    switch (decision) {
        case 0:
            //ebpf_print("VRF %s, new wins (process run %llu)\n", info->name, st_sh->counter);
            return BGP_ROUTE_TYPE_NEW;
        case 1:
        case 2:
            //ebpf_print("VRF %s, old wins (process run %llu)\n", info->name, st_sh->counter);
            return BGP_ROUTE_TYPE_OLD;
        default:
            next();
            return BGP_ROUTE_TYPE_FAIL;
    }
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};

            uint64_t ret_val = alternate_old_new(&args);

            p_assert(ret_val == BGP_ROUTE_TYPE_UNKNOWN ||
                    ret_val == BGP_ROUTE_TYPE_FAIL ||
                   ret_val == BGP_ROUTE_TYPE_NEW ||
                   ret_val == BGP_ROUTE_TYPE_OLD);

            ctx_shmrm(42);

            return 0;
        }
)
