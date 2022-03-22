//
// Created by thomas on 16/06/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"

#define MAX_METRIC 5000

#include "../prove_stuffs/prove.h"

/* starting point */
uint64_t export_igp_metric(args_t *args UNUSED);


PROOF_INSTS(

        uint64_t nondet_u64(void);
        uint8_t nondet_u8(void);

        struct ubpf_nexthop *get_nexthop(struct ubpf_prefix *pfx) {
            struct ubpf_nexthop *nxthop;

            nxthop = malloc(sizeof(*nxthop));
            if (!nxthop) return NULL;

            nxthop->route_type = nondet_u8(); // connected, static, kernel
            nxthop->igp_metric = nondet_u64();

            return nxthop;
        }

        struct ubpf_peer_info *get_src_peer_info() {
            struct ubpf_peer_info *peer;

            peer = malloc(sizeof(*peer));
            if (!peer) return NULL;

            return peer;
        }

#define NEXT_RETURN_VALUE PLUGIN_FILTER_UNKNOWN
)

#define TIDYING    \
PROOF_INSTS( do {  \
    free(nexthop); \
    free(peer);    \
} while (0))

PROOF_T2_INSTS(
        void *rnd_ptr(void);
)

uint64_t export_igp_metric(args_t *args UNUSED) {
    // int nb_peers;
    struct ubpf_nexthop *nexthop;
    struct ubpf_peer_info *peer;
    nexthop = get_nexthop(NULL);

#ifdef PROVERS_T2
    peer = rnd_ptr();
#else
    peer = get_src_peer_info();
#endif

    if (!nexthop || !peer) next();

    if (peer->peer_type != EBGP_SESSION) { // may be optional
        TIDYING;
        next();
        return PLUGIN_FILTER_UNKNOWN;
    }

    if (nexthop->igp_metric <= MAX_METRIC) {
        TIDYING;
        next(); // the route is accepted by this filter;
        // next filter will decide whether the route is exported
    }

    TIDYING;
    return PLUGIN_FILTER_REJECT;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};

            uint64_t ret_val = export_igp_metric(&args);

            PROOF_SEAHORN_INSTS(
                    RET_VAL_FILTERS_CHECK(ret_val);

            )
            return 0;
        }
)
