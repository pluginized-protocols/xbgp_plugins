//
// Created by thomas on 20/07/21.
//
#include "../xbgp_compliant_api/xbgp_plugin_api.h"

#ifdef PROVERS_SH
#include "../prove_stuffs/mod_ubpf_api.h"
#endif

#ifdef PROVERS

int nondet_len();

int get_vrf(struct vrf_info *vrf_info) {
    const char *my_vrf = "red"
    if (!vrf_info) return -1;

    if (vrf_info->str_len >= vrf_name_len) {
        strncpy(vrf_info->name, my_vrf, sizeof(my_vrf));
    }
    info->vrf_id = non_detlen();
    return 0;
}

#endif

void *memset(void *s, int c, size_t n);

struct stats {
    int choice;
    unsigned long long int counter;
};

static __always_inline int
strncmp(const char *s1, const char *s2, register size_t n)
{
    register unsigned char u1, u2;
    while (n-- > 0)
    {
        u1 = (unsigned char) *s1++;
        u2 = (unsigned char) *s2++;
        if (u1 != u2)
            return u1 - u2;
        if (u1 == '\0')
            return 0;
    }
    return 0;
}


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

    if (strncmp(info->name, "red", 4) != 0) {
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

#ifdef PROVER_SH
int main(void) {
    args_t args = {};

    uint64_t ret_val =  dumb_decision(&args);

    assert(ret_val == BGP_ROUTE_TYPE_FAIL ||
           ret_val == BGP_ROUTE_TYPE_NEW ||
           ret_val == BGP_ROUTE_TYPE_OLD);

    return 0;
}
#endif