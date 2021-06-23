//
// Created by thomas on 15/05/20.
//

#include <bytecode_public.h>
#include "router_bgp_config.h"
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../prove_stuffs/prove.h"


// for static fixed size only (and because of -O2)!
void *memcpy(void *dest, const void *src, size_t n);

#ifdef PROVERS
struct ubpf_peer_info *get_peer_info(UNUSED int *nb_peers) {
    struct ubpf_peer_info *pf;
    pf = malloc(sizeof(*pf));
    if (!pf) {
        return NULL;
    }
    pf->peer_type = EBGP_SESSION;

    return pf;
}

#include "../prove_stuffs/mod_ubpf_api.c"
#endif

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

#ifdef PROVERS_SH
    CHECK_ATTR_FORMAT(originating_prefix, 8);
#endif

    if (set_attr(originating_prefix) == -1) {
        ebpf_print("Error, Unable to add attribute\n");
    }

    return PLUGIN_FILTER_ACCEPT;
}

#ifdef PROVERS
int main(void) {
    args_t args = {};
    uint64_t ret_val = add_prefix_originator(&args);

#ifdef PROVERS_SH
    RET_VAL_FILTERS_CHECK(ret_val);
#endif
    return 0;
}
#endif