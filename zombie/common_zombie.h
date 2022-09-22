#ifndef XBGP_COMMON_ZOMBIE_H
#define XBGP_COMMON_ZOMBIE_H

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
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

typedef union typeunion {
    void *v;
    const char* cchr;
} typeptr;

#define FOREACH_TYPE(TYPE) \
TYPE(RECEIVED)   \
TYPE(WITHDRAW)  \
TYPE(UPDATE)   \
TYPE(REQUEST)   \
TYPE(NEEDED)   \

#define GENERATE_ENUM(ENUM) ENUM,
#define GENERATE_STRING(STRING) #STRING,

enum TYPE_ENUM {
    FOREACH_TYPE(GENERATE_ENUM)
};


static const char *TYPE_STRING[] = {
        FOREACH_TYPE(GENERATE_STRING)
};

/**
 * Log a prefix and its related action
 */
#ifdef DEBUG
static __always_inline void log_prefix(int l, uint8_t* data, enum TYPE_ENUM type)
{
    struct timespec time;
    get_time(&time);
    typeptr t;
    t.cchr = TYPE_STRING[type];
    ebpf_print("[%i,%i] %s: ", LOG_INT(time.tv_sec), LOG_SLONG(time.tv_nsec), LOG_STR(t.v));
    if (l > 32)
        ebpf_print("IPv6");
    else
    {
        int j;
        for (j = 0 ; j < size_pfx(l) ; j++)
            ebpf_print(j<3 ? "%i." : "%i", LOG_INT(data[j]));
        for (; j < 4 ; j++)
            ebpf_print(j<3 ? "%i." : "%i", LOG_INT(0));
    }
    ebpf_print("/%i\n", LOG_INT(l));
}
#else
#define log_prefix(...)
#endif

static __always_inline void print_pfx_struct(struct ubpf_prefix* pfx)
{
    dbg_print("print_pfx_struct\n");
    dbg_print("struct: {");
    dbg_print("afi: %i, ", LOG_INT(pfx->afi));
    dbg_print("safi: %i, ", LOG_INT(pfx->safi));
    dbg_print("pfx: ");
    int j;
    for (j = 0 ; j < size_pfx(pfx->prefixlen) && j < 4 ; j++)
        dbg_print(j<3 ? "%i." : "%i", LOG_INT(pfx->u[j]));
    for (; j < 4 ; j++)
        dbg_print(j<3 ? "%i." : "%i", LOG_INT(0));
    dbg_print("/%i}\n", LOG_INT(pfx->prefixlen));
}

static __always_inline void print_pfx_buf(uint8_t* data)
{
    dbg_print("print_pfx_buf\n");
    dbg_print("buffer: {");
    dbg_print("afi: %i, ", LOG_INT(ebpf_ntohs(*(uint16_t *)data)));
    data += sizeof(uint16_t);
    dbg_print("safi: %i, ", LOG_INT(*data));
    data += sizeof(uint8_t);
    dbg_print("pfx: ");
    int l = ebpf_ntohs(*(uint16_t *)data);
    data += sizeof(uint16_t);
    int j;
    for (j = 0 ; j < size_pfx(l) ; j++)
        dbg_print(j<3 ? "%i." : "%i", LOG_INT(data[j]));
    for (; j < 4 ; j++)
        dbg_print(j<3 ? "%i." : "%i", LOG_INT(0));
    dbg_print("/%i}\n", LOG_INT(l));
}


/*char space[SIZE_MEMORY_SPACE];*/
char* space; /*remove the malloc in init*/
struct pf* next_pref;
struct host* next_host;
struct ubpf_peer_info NULL_host;

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

/**
 * Set the data structure
 */
static __always_inline void init();

/**
 * Reset the data structure
 */
static __always_inline void reinit();

/**
 * Delete the data structure
 */
static __always_inline void destruct();

/**
 * Iterates on a list of prefix
 * @param host The host on which we iterate on the prefixes
 * @param current A pointer to the current prefix. Side effect: modifies *current with the new prefix address
 * @return 0 if there is no more prefix in the list, 1 otherwise
 */
static __always_inline int nextPref(struct host* host, struct pf** current);

/**
 * Iterates on a list of prefix and free each visited prefix
 * @param host The host on which we iterate on the prefixes
 * @param current A pointer to the current prefix. Side effect: modifies *current with the new prefix address
 * @return 0 if there is no more prefix in the list, 1 otherwise
 */
static __always_inline int nextPrefAndClean(struct host* host, struct pf** current);

/**
 * Iterates on a list of hosts
 * @param current A pointer to the current host. Side effect: modifies *current with the new host address
 * @return 0 if there is no more host in the list, 1 otherwise
 */
static __always_inline int nextHost(struct host** current);

/**
 * Adds a prefix to the data structure
 * @param host The peer on which we add a prefix
 * @param pref The prefix to add
 * @return -1 if there is not enough space in the data structure, 0 otherwise
 */
static __always_inline int addPref(struct ubpf_peer_info* host, ll_element* pref);
#ifdef USE_ROUTE
static __always_inline void printRte(struct host* current_host)
{
    dbg_print("printRte\n");
    struct pf* current_pfx = current_host->first;
    int i;
    do {
        ebpf_print("->");
        for (i = 0 ; i < current_pfx->rte->pfx.prefixlen/8 + ((current_pfx->rte->pfx.prefixlen%8) != 0) ; i++)
            ebpf_print(i<3 ? "%i." : "%i", LOG_INT(current_pfx->rte->pfx.u[i]));

        for (; i < 4 ; i++)
            ebpf_print(i<3 ? "0." : "0");
        ebpf_print("/%i", LOG_INT(current_pfx->rte->pfx.prefixlen));
        i = current_pfx != current_host->last;
        current_pfx = current_pfx->next;
    } while (i);
    ebpf_print("\n");
}
#endif
static __always_inline void printList()
{
    for (struct host* current_host = (struct host*) space ; current_host < next_host ; current_host++)
    {
        ebpf_print("+----------------+\n");
        char prefix_addr[52];
        for (size_t j = 0 ; j < sizeof(prefix_addr) ; j++)
            prefix_addr[j] = 0;
        ebpf_inet_ntop((uint8_t*)&(current_host->h->addr.addr), current_host->h->addr.af, prefix_addr, sizeof(prefix_addr));
        ebpf_print("| %-14s |", LOG_STR(prefix_addr));
#ifdef USE_ROUTE
        printRte(current_host);
#endif
        ebpf_print("+----------------+\n");
        ebpf_print("        |         \n");
        ebpf_print("        V         \n");
    }
    ebpf_print("        X         \n");
}

static __always_inline void reinit()
{
    next_host = (struct host*) space;
    next_pref = (struct pf*) (space + SIZE_MEMORY_SPACE - sizeof(struct pf));
}
static __always_inline void init()
{
    space = ctx_malloc(SIZE_MEMORY_SPACE);
    memset(&NULL_host, 0, sizeof(struct ubpf_peer_info));
    reinit();
}

static __always_inline void destruct()
{
    ctx_free(space);
}

/**
 * Tell if there is still enough place in the buffer
 * @return 0 if no,
 *         1 if enough for a struct pf,
 *         2 if enough for a struct host,
 *         >2 if enough for a struct host + 1 struct pf
 */
static __always_inline int enoughSpace()
{
    char* b = (char*) next_host;
    char* e = (char*) next_pref;
    e += sizeof(struct pf);
    unsigned long diff = (unsigned long) (e-b)/8;
    if(3 * sizeof(struct pf) == 2 * sizeof(struct host))
        return diff/3 +  (diff+1)/3;
    else
    {
        if (diff >= sizeof(struct pf) + sizeof(struct host))
            return 3;
        if (diff >= sizeof(struct host))
            return 2;
        if (diff >= sizeof(struct pf))
            return 1;
    }
    return 0;
}

static __always_inline int nextHost(struct host** current)
{
    struct host* up = *current;
    up++;
    *current = up;

    return *current < next_host;
}

static __always_inline int nextPref(struct host* host, struct pf** current)
{
    if (next_host == (struct host*) space && next_pref == (struct pf*) (space + SIZE_MEMORY_SPACE - sizeof(struct pf)))
        return 0; // there is no list yet
    if (*current == host->last)
        return 0;

    struct pf* up = *current;
    up = up->next;
    *current = up;

    return 1;
}

static __always_inline int nextPrefAndClean(struct host* host, struct pf** current)
{
    if (next_host == (struct host*) space && next_pref == (struct pf*) (space + SIZE_MEMORY_SPACE - sizeof(struct pf)))
        return 0; // there is no list yet
    if (*current == host->last)
        return 0;
    struct pf* up = *current;
    up = up->next;
#ifndef USE_ROUTE
    ctx_free((*current)->pfx);
#endif
    ctx_free(*current);
    *current = up;

    return 1;
}

#endif //XBGP_COMMON_ZOMBIE_H
