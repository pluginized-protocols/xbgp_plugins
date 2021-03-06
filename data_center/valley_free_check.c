//
// Created by thomas on 3/06/20.
//

#include <stddef.h>
#include <sys/cdefs.h>
#include <bytecode_public.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_datacenter.h"
#include "../byte_manip.h"

#define MAX_DC_ROUTERS INT32_MAX

#include "../prove_stuffs/prove.h"

#ifdef PROVERS
uint8_t *nondet_get_buf__verif();
struct ubpf_peer_info *nondet_get_pinfo__verif();
uint16_t nondet_get_u16__verif();

struct ubpf_peer_info *get_peer_info(int *nb_peers) {
    struct ubpf_peer_info *pinfo = nondet_get_pinfo__verif();
    pinfo->peer_type = IBGP_SESSION;
    return pinfo;
}

struct ubpf_peer_info *get_src_peer_info() {
    struct ubpf_peer_info *pinfo = nondet_get_pinfo__verif();
    pinfo->peer_type = IBGP_SESSION;
    return pinfo;
}


struct path_attribute *get_attr_from_code(uint8_t code) {
    struct path_attribute *p_attr;
    p_attr = malloc(sizeof(*p_attr));

    switch (code) {
        case AS_PATH_ATTR_ID:
            p_attr->code = AS_PATH_ATTR_ID;
            p_attr->flags = ATTR_TRANSITIVE;
            p_attr->length = nondet_get_u16__verif() * 4;
            memcpy(p_attr->data, nondet_get_buf__verif(), p_attr->length);
            break;
        default:
            //p_assert(0);
            return NULL;
    }
    return NULL;
}

#define next() return PLUGIN_FILTER_UNKNOWN
#include "../prove_stuffs/mod_ubpf_api.c"
#endif


/* only for static arrays !!! */
void *memset(void *s, int c, size_t n);

enum type_router {
    TYPE_SPINE,
    TYPE_TOR,
    TYPE_UNKNOWN
};

enum type_router __always_inline get_type(const char *type) {

    return ebpf_memcmp(type, "spine", 5) == 0 ? TYPE_SPINE :
           ebpf_memcmp(type, "tor", 3) == 0 ? TYPE_TOR : TYPE_UNKNOWN;

};

int __always_inline valley_check(uint32_t as1, uint32_t as2) {

    uint32_t as;
    enum type_router as1_type = TYPE_UNKNOWN;
    enum type_router as2_type = TYPE_UNKNOWN;
    char type[10];

    struct global_info info;
    struct global_info current_as_type;
    struct global_info current_as;
    struct global_info current_type;

    if (get_extra_info("topo_data_center", &info) != 0) return -1;

    int i;

    for (i = 0; i < MAX_DC_ROUTERS - 1; i++) {

        if (get_extra_info_lst_idx(&info, i, &current_as_type) != 0) return -1;

        if (get_extra_info_lst_idx(&current_as_type, 0, &current_as) != 0) return -1;
        if (get_extra_info_lst_idx(&current_as_type, 1, &current_type) != 0) return -1;

        memset(type, 0, sizeof(type));

        if (get_extra_info_value(&current_type, type, 9) != 0) return -1;
        if (get_extra_info_value(&current_type, &as, sizeof(as)) != 0) return -1;

        if (as == as1) as1_type = get_type(type);
        else if (as == as2) as2_type = get_type(type);

        if (as1_type != TYPE_UNKNOWN && as2_type != TYPE_UNKNOWN) {

            if (as1_type == TYPE_SPINE && as2_type == TYPE_TOR) return 0;

        }

    }

    if (as1_type == TYPE_UNKNOWN || as2_type == TYPE_UNKNOWN) return -1;
    return 1;
}


int __always_inline flatten_as_path(const uint8_t *as_path, unsigned int length, unsigned int *asp_flat, int flat_size) {
    unsigned int bytes = 0;
    unsigned int dummy = 0;
    uint8_t segment_length;
    unsigned int j;
    int idx = 0;
    unsigned int seg_size;

    if (length < 6) return -1;
    if (length > 4096) return -1;
    if (length % 2) return -1;

    while (bytes < length && dummy < length) {
        segment_length = as_path[bytes+1];

        if (segment_length <= 0) return -1;
        if (segment_length > 255) return -1;

        for (j = 0; j < segment_length && idx < flat_size && idx >= 0; j++) {
            unsigned int ofst = *(unsigned int *) (as_path + bytes + 2 + (4 * j));
            asp_flat[idx] = get_u32_t2_friendly(ofst);
            idx++;
        }

        seg_size = (segment_length * 4) + 2;
        if (seg_size + bytes > length) return -1;

        bytes += seg_size;

        /* increment dummy to the minimal segment length value for T2*/
        dummy += 6;

    }
    return idx;
}


uint64_t valley_free_check(args_t *args UNUSED) {
    int i;
    int nb_ases;
    uint8_t *as_path;
    uint32_t *arr_aspath;
    uint32_t my_as;
    unsigned int as_path_len;
    struct ubpf_peer_info *peer;
    struct path_attribute *attr;

    attr = get_attr_from_code(AS_PATH_ATTR_CODE);
    peer = get_src_peer_info();
    if (!attr || !peer) return PLUGIN_FILTER_UNKNOWN;
    my_as = peer->local_bgp_session->as;
    as_path = attr->data;
    as_path_len = attr->length;

    arr_aspath = ctx_malloc(sizeof(*arr_aspath) * 1024);
    if (!arr_aspath) return PLUGIN_FILTER_UNKNOWN;

    nb_ases = flatten_as_path(as_path, as_path_len, arr_aspath, 1024);
    if (nb_ases == -1) return PLUGIN_FILTER_UNKNOWN;

    // should always contains at least one AS !
    if (!valley_check(arr_aspath[0], my_as)) return PLUGIN_FILTER_REJECT;

    for (i = 1; i < nb_ases; i++) {
        if (!valley_check(arr_aspath[i], my_as)) return PLUGIN_FILTER_REJECT;
    }
    next();
    return PLUGIN_FILTER_REJECT;
}

#ifdef PROVERS
int main(void) {
    args_t args = {};
    uint64_t ret_val = valley_free_check(&args);
#ifdef PROVERS_SH
    RET_VAL_FILTERS_CHECK(ret_val);
#endif
    return 0;
}
#endif