//
// Created by thomas on 16/06/20.
//

#include <stdint.h>
#include <bytecode_public.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"

#define MAX_METRIC 5000

#include "../prove_stuffs/prove.h"

/* starting point */
uint64_t export_igp(args_t *args UNUSED);


#define NEXT_RETURN_VALUE PLUGIN_FILTER_UNKNOWN

#ifdef PROVERS_SH
#define next() return PLUGIN_FILTER_UNKNOWN
#endif

uint64_t export_igp(args_t *args UNUSED) {

    int nb_peers;
    struct ubpf_nexthop *nexthop;
    struct ubpf_peer_info *peer;
    nexthop = get_nexthop(NULL);
    peer = get_src_peer_info(&nb_peers);

    if (!nexthop || !peer) next();

    if (peer->peer_type != EBGP_SESSION) { // may be optional
        next();
    }

    if (nexthop->igp_metric <= MAX_METRIC) {
        next(); // the route is accepted by this filter;
        // next filter will decide whether the route is exported
    }

    return PLUGIN_FILTER_REJECT;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};

            uint64_t ret_val = export_igp(&args);

            PROOF_SEAHORN_INSTS(
                    RET_VAL_FILTERS_CHECK(ret_val);

            )
            return 0;
        }
)
