#ifndef DEL_BGP_ROUTE_C
#define DEL_BGP_ROUTE_C
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../prove_stuffs/prove.h"

T2SI void del_bgp_route(struct bgp_route *rte) {
    int i;
    if (!rte) return;

    if (rte->peer_info) {
        if (rte->peer_info->local_bgp_session != NULL) {
            ctx_free(rte->peer_info->local_bgp_session);
        }
        ctx_free(rte->peer_info);
    }

    if (rte->attr) {
        for (i = 0; i < rte->attr_nb; i++) {
            if (rte->attr[i]) ctx_free(rte->attr[i]);
        }
        ctx_free(rte->attr);
    }
    ctx_free(rte);
}
#endif