#ifndef MY_FOR
#define MY_FOR
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../prove_stuffs/prove.h"
#define USE_ROUTE
#include "common_zombie.h"
#ifndef PROVERS_T2
#include "del_bgp_route.c"
#else
static __always_inline void del_bgp_route(struct bgp_route *rte);
#endif

T2SI unsigned long my_for(uint8_t* buf, struct pf* pf_cur, struct host* host_cur) {
    unsigned long i;
    int cont = 1;

    for (i = 0 ; i < (4096-19-sizeof(struct ubpf_prefix)) && cont ;)
    {  //iterate on the different prefix in the same message
	uint16_t* buf_s;
#ifdef HARD_DEBUG
	uint8_t* b_buf = buf+i;
#endif
	buf_s = (uint16_t *) (buf+i);
	*buf_s = ebpf_htons(pf_cur->rte->pfx.afi);
	i += 2;
	buf[i] = pf_cur->rte->pfx.safi;
	i += 1;
	buf_s = (uint16_t *) (buf+i);
	*buf_s = ebpf_htons(pf_cur->rte->pfx.prefixlen);
	i += 2;
    PROOF_T2_INSTS(
            memcpy(buf+i, pf_cur->rte->pfx.u, size_pfx(pf_cur->rte->pfx.prefixlen));
	        i += 1; // size of the prefix is strictly positif
    )
    NOT_T2(
            for (int j = 0 ; j < size_pfx(pf_cur->rte->pfx.prefixlen) ; j++)
                buf[i++] = pf_cur->rte->pfx.u[j];
            )
#ifdef HARD_DEBUG
	print_pfx_struct(&(pf_cur->rte->pfx));
	print_pfx_buf(b_buf);
#endif
	log_prefix(pf_cur->rte->pfx.prefixlen, pf_cur->rte->pfx.u, REQUEST);
	del_bgp_route(pf_cur->rte);
	cont = nextPref(host_cur, &pf_cur);
    }
    return i;
}
#endif