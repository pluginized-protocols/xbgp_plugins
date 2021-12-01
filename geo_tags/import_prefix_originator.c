//
// Created by thomas on 15/05/20.
//

#include <bytecode_public.h>
#include "router_bgp_config.h"
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../prove_stuffs/prove.h"

/* starting point*/
uint64_t add_prefix_originator(args_t *args UNUSED);

PROOF_INSTS(
        struct ubpf_peer_info *get_peer_info(UNUSED int *nb_peers) {
            struct ubpf_peer_info *pf;
            pf = malloc(sizeof(*pf));
            if (!pf) {
                return NULL;
            }
            pf->peer_type = EBGP_SESSION;

            return pf;
        }
)


uint64_t add_prefix_originator(args_t *args UNUSED) {

    uint64_t _attr;
    int nb_peers;
    struct path_attribute *originating_prefix;
    uint8_t buf[sizeof(*originating_prefix) + sizeof(uint64_t)];
    struct ubpf_peer_info *peer = get_src_peer_info(&nb_peers);

    originating_prefix = (struct path_attribute *) buf;

    if (peer->peer_type != EBGP_SESSION) {

        const char *tp = peer->peer_type == IBGP_SESSION ? "ibgp" :
                         peer->peer_type == EBGP_SESSION ? "ebgp" :
                         peer->peer_type == LOCAL_SESSION ? "local" :
                         "unk wtf ?";

        ebpf_print("Not an eBGP session %s (%u)\n", tp, peer->router_id);
        next();
    }

    /* the peer is eBGP -> the prefix is outside the our AS, need to add our coordinate */
    _attr = coord_to_attr(&this_router_coordinate);

    originating_prefix->code = PREFIX_ORIGINATOR;
    originating_prefix->flags = 0x80;
    originating_prefix->length = 8;
    memcpy(originating_prefix->data, &_attr, sizeof(uint64_t));

    PROOF_SEAHORN_INSTS(
            CHECK_ATTR_FORMAT(originating_prefix, 8);
    )


    if (set_attr(originating_prefix) == -1) {
        ebpf_print("Error, Unable to add attribute\n");
    }

    return PLUGIN_FILTER_ACCEPT;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = add_prefix_originator(&args);

            PROOF_SEAHORN_INSTS(
                    RET_VAL_FILTERS_CHECK(ret_val);
            )
            return 0;
        }
)