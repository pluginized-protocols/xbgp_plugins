//
// Created by thomas on 15/05/20.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "router_bgp_config.h"
#include "../prove_stuffs/prove.h"

/* starting point*/
uint64_t import_prefix_originator(args_t *args UNUSED);

PROOF_INSTS(

        uint8_t nondet_u8(void);

        struct ubpf_peer_info *get_src_peer_info() {
            struct ubpf_peer_info *pf;
            pf = malloc(sizeof(*pf));
            if (!pf) {
                return NULL;
            }
            pf->peer_type = nondet_u8();

            return pf;
        }
#define NEXT_RETURN_VALUE PLUGIN_FILTER_UNKNOWN
)

#define TIDYING         \
PROOF_INSTS(do {        \
  if (peer) free(peer); \
} while(0))

uint64_t import_prefix_originator(args_t *args UNUSED) {

    uint64_t _attr;
    int nb_peers;
    struct path_attribute *originating_prefix;
    uint8_t buf[sizeof(*originating_prefix) + sizeof(uint64_t)];
#ifndef PROVERS_T2
    struct ubpf_peer_info *peer = get_src_peer_info();
#else
    struct ubpf_peer_info *peer = rnd_ptr();
#endif
    if (!peer) {
        next();
        return PLUGIN_FILTER_UNKNOWN;
    }

    originating_prefix = (struct path_attribute *) buf;

    if (peer->peer_type != EBGP_SESSION) {

        const char *tp = peer->peer_type == IBGP_SESSION ? "ibgp" :
                         peer->peer_type == EBGP_SESSION ? "ebgp" :
                         peer->peer_type == LOCAL_SESSION ? "local" :
                         "unk wtf ?";

        ebpf_print("Not an eBGP session %s (%u)\n", LOG_PTR(tp), LOG_U32(peer->router_id));
        TIDYING;
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

    TIDYING;

    return PLUGIN_FILTER_ACCEPT;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = import_prefix_originator(&args);

            PROOF_SEAHORN_INSTS(
                    RET_VAL_FILTERS_CHECK(ret_val);
            )
            return 0;
        }
)