//
// Created by thomas on 15/05/20.
//

#include <bytecode_public.h>
#include "router_bgp_config.h"
#include "../xbgp_compliant_api/xbgp_plugin_api.h"

uint64_t add_prefix_originator(args_t *args UNUSED) {

    uint64_t attr;
    int nb_peers;
    struct path_attribute originating_prefix;
    struct ubpf_peer_info *peer = get_peer_info(&nb_peers);

    if (peer->peer_type != EBGP_SESSION) {
        ebpf_print("Not an eBGP session\n");
        next();
    }

    /* the peer is eBGP -> the prefix is outside the our AS, need to add our coordinate */
    attr = coord_to_attr(&this_router_coordinate);

    originating_prefix.code = PREFIX_ORIGINATOR;
    originating_prefix.flags = 0x80;
    originating_prefix.len = 8;
    originating_prefix.data = (uint8_t *) &attr;

    if (set_attr(&originating_prefix) == -1) {
        ebpf_print("Error, Unable to add attribute\n");
    }

    return PLUGIN_FILTER_ACCEPT;
}