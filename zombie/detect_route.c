#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#define USE_ROUTE
#include "common_zombie.h"
#include "../prove_stuffs/prove.h"
#define ROUTE_TYPE_BGP 9

#ifndef PROVERS_T2
#include "addPref.c"
#include "send_request.c"
#else
static __always_inline void send_request();
static __always_inline void del_bgp_route(struct bgp_route *rte);
static __always_inline int addPref(struct ubpf_peer_info* host, ll_element* pref);
#endif

T2SI uint64_t detect_route(unsigned int it, time_t expiration)
{
    struct bgp_route* current_route = next_rib_route(it);
    uint64_t ret = 0;
    PROOF_T2_INSTS(int i = 0;)
    while (current_route != NULL PROOF_T2_INSTS(&& i++ < 1000000)) // iterate on the routes in the rib && adding a bound
    {
        ret = 1;
        if (current_route->route_info.uptime < expiration && current_route->route_info.type == ROUTE_TYPE_BGP)
        {  // if a route timeout, we add it in the data structure
            if (current_route->pfx.afi == 1)
                log_prefix(current_route->pfx.prefixlen, current_route->pfx.u, NEEDED);

            int err = addPref(current_route->peer_info, current_route);

            if (err != 0) // if there is no space left in the data structure, we empty it by sending the requests
            {
                send_request();
                addPref(current_route->peer_info, current_route);
            }
        }
        else
        {
            del_bgp_route(current_route);
        }
        current_route = next_rib_route(it);
    }
    return ret;
}
