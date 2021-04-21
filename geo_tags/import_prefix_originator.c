//
// Created by thomas on 15/05/20.
//

#include <bytecode_public.h>
#include "router_bgp_config.h"
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../xbgp_compliant_api/xbgp_defs.h"

// for static fixed size only !
void *memcpy(void *dest, const void *src, size_t n);

uint64_t add_prefix_originator(args_t *args UNUSED) {

    uint64_t _attr;
    int nb_peers;
    struct path_attribute *originating_prefix;
    uint8_t buf[sizeof(*originating_prefix) + sizeof(uint64_t)];
    struct ubpf_peer_info *peer = get_peer_info(&nb_peers);

    originating_prefix = (struct path_attribute *) buf;

    if (peer->peer_type != EBGP_SESSION) {
        ebpf_print("Not an eBGP session\n");
        next();
    }

    /* the peer is eBGP -> the prefix is outside the our AS, need to add our coordinate */
    _attr = coord_to_attr(&this_router_coordinate);

    originating_prefix->code = PREFIX_ORIGINATOR;
    originating_prefix->flags = 0x80;
    originating_prefix->length = 8;
    memcpy(originating_prefix->data, &_attr, sizeof(uint64_t));

    //CHECK_ATTR_FORMAT(originating_prefix, 8);

    if (set_attr(originating_prefix) == -1) {
        ebpf_print("Error, Unable to add attribute\n");
    }

    return PLUGIN_FILTER_ACCEPT;
}