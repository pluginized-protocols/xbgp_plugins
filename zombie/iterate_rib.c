#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#define USE_ROUTE
#include "common_zombie.h"
#include "../prove_stuffs/prove.h"
#define ROUTE_TYPE_BGP 9

#define mal_init(x) x = malloc(sizeof(x))
#define mal_initp(x) x = malloc(sizeof(*x))

PROOF_INSTS(
        int32_t nondet_i32(void);
        long int nondet_li(void);
        int nondet_i(void);
        struct bgp_route* next_rib_route(unsigned int itv4)
        {
            struct bgp_route* rte = malloc(sizeof(struct bgp_route));
            if (rte) {
                mal_initp(rte->peer_info);
                if (rte->peer_info) {
                    mal_init(rte->peer_info->local_bgp_session);
                }
                int tmp = nondet_i();
                tmp /= 2;
                tmp = tmp < 0 ? -tmp : tmp;
                rte->attr_nb = ((unsigned int) tmp)%256;
                rte->attr = malloc(rte->attr_nb * sizeof(rte->attr));
                if (rte->attr) {
                    for (int i = 0; i < rte->attr_nb; i++) {
                        mal_init(rte->attr[i]);
                    }
                }
            }
            return rte;
        }

        int new_rib_iterator(int afi, int safi) {
            return 1;
        }

        int clock_gettime(clockid_t clk_id, struct timespec *tp) {
            tp->tv_sec = nondet_i32();
            tp->tv_nsec = nondet_li();
            return 0;
        }
        )

uint64_t iterate_rib(args_t *args UNUSED);

#ifndef PROVERS_T2
#include "addPref.c"
#include "detect_route.c"
#include "send_request.c"
#else
static __always_inline uint64_t detect_route(unsigned int it, time_t expiration);
static __always_inline void send_request();
#endif

uint64_t iterate_rib(args_t *args UNUSED) {
    // getting the IPv4 and IPv6 iterators
    unsigned int itv4 = new_rib_iterator(1, 1);
    unsigned int itv6 = new_rib_iterator(2, 1);
    init(); //init the data structure
    struct timespec time;
    get_time(&time);

#ifdef PROVERS
    time_t expiration = time.tv_sec > 24*60*60 ? time.tv_sec - 24*60*60 : 0;
#else
    time_t expiration = time.tv_sec - 5;
#endif
    int ret;
    ret = detect_route(itv4, expiration);
    ret += detect_route(itv6, expiration);

    // generate and send the messages
    if (ret)
        send_request();
    time_t t = 10;
    reschedule_plugin(&t);
    return 0;
}

PROOF_INSTS(
    int main(void) {
        args_t args = {};
        uint64_t ret;
        ret = iterate_rib(&args);
	return 0;
    }
    )
