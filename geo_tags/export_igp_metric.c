//
// Created by thomas on 16/06/20.
//

#include "../../public_bpf.h"
#include "../../ubpf_prefix.h"
#include "ubpf_api.h"

#define MAX_METRIC 5000

uint64_t export_igp(bpf_full_args_t *args UNUSED) {

    int nb_peers;
    struct ubpf_nexthop *nexthop;
    struct ubpf_peer_info *peer;
    nexthop = get_nexthop(NULL);
    peer = get_peer_info(&nb_peers);

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