#ifndef ADDPREF_C
#define ADDPREF_C
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../prove_stuffs/prove.h"
#include <string.h>

#define TYPE_REQUEST 8
#define SIZE_MEMORY_SPACE 640

#define size_pfx(pfx_len) \
pfx_len/8 + (pfx_len%8 != 0)

#ifdef DEBUG
#define dbg_print(fmt, ...) ebpf_print(fmt, ##__VA_ARGS__)
#else
#define dbg_print(fmt, ...)
#endif

/*char space[SIZE_MEMORY_SPACE];*/
PROOF_T2_INSTS(
        char* space; /*remove the malloc in init*/
        struct pf* next_pref;
        struct host* next_host;
        struct ubpf_peer_info NULL_host;
)

#ifndef STRUCT_PF
#define STRUCT_PF
#ifdef USE_ROUTE
typedef struct bgp_route ll_element;
struct pf {
    ll_element* rte;
    struct pf* next;
};
#else
typedef struct ubpf_prefix ll_element;
struct pf {
    ll_element* pfx;
    struct pf* next;
};
#endif
struct host {
    struct ubpf_peer_info* h;
    struct pf* first;
    struct pf* last;
};
#endif

static __always_inline int addOnlyPref(struct host* host, ll_element* pref)
{
    if (enoughSpace() < 1)
        return -1;
    host->last->next = next_pref;
    host->last = next_pref;
#ifdef USE_ROUTE
    next_pref->rte = pref;
#else
    next_pref->pfx = pref;
#endif
    struct pf* cur = next_pref;
    next_pref--;
    cur->next = next_pref;
    return 0;
}

static __always_inline int addHostAndPref(struct ubpf_peer_info* host, ll_element* pref)
{
    if (enoughSpace() < 3)
        return -1;
    next_host->h = host;
    next_host->first = next_pref;
    next_host->last = next_pref;
#ifdef USE_ROUTE
    next_pref->rte = pref;
#else
    next_pref->pfx = pref;
#endif
    next_pref--;
    next_host++;
    return 0;
}

T2SI int addPref(struct ubpf_peer_info* host, ll_element* pref)
{
    PROOF_T2_INSTS(int j = 0);
    for (struct host* i = (struct host*) space ; i < next_host PROOF_T2_INSTS(&& j++ < SIZE_MEMORY_SPACE) ; i++)
    {
        if (!memcmp(i->h, host, sizeof(struct ubpf_peer_info)))
            return addOnlyPref(i, pref);
    }
    return addHostAndPref(host, pref);
}
#endif