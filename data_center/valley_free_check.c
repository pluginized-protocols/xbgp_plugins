//
// Created by thomas on 3/06/20.
//

#include "../../public_bpf.h"
#include "ubpf_api.h"
#include "common_datacenter.h"
#include "../byte_manip.h"


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

    for (i = 0;; i++) {

        if (get_extra_info_lst_idx(&info, i, &current_as_type) != 0) return -1;

        if (get_extra_info_lst_idx(&current_as_type, 0, &current_as) != 0) return -1;
        if (get_extra_info_lst_idx(&current_as_type, 1, &current_type) != 0) return -1;

        memset(type, 0, sizeof(char) * 10);

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


uint64_t valley_free_check(bpf_full_args_t *args UNUSED) {

    uint8_t *as_path;
    uint8_t segment_length;
    uint8_t segment_type;

    uint32_t curr_as, next_as;

    uint32_t my_as;
    int as_path_len;
    int i = 0;
    int j;

    int is_beginning = 1;

    struct ubpf_peer_info *peer;

    struct path_attribute *attr;
    attr = get_attr_from_code(AS_PATH_ATTR_CODE);

    peer = get_src_peer_info();
    if (!attr || !peer) return FAIL;
    my_as = peer->local_bgp_session->as;

    as_path = attr->data;
    as_path_len = attr->len;

    while (i < as_path_len) {
        segment_type = as_path[i++];
        segment_length = as_path[i++];

        for (j = 0; j < segment_length - 1; j++) {

            curr_as = get_u32(as_path + i);
            i += 4;

            if (is_beginning) {
                if (!valley_check(curr_as, my_as)) return PLUGIN_FILTER_REJECT;
                is_beginning = 0;
            }

            next_as = get_u32(as_path + i);
            i += 4;

            if (!valley_check(next_as, curr_as)) return PLUGIN_FILTER_REJECT;

        }
    }
    next();
    return PLUGIN_FILTER_REJECT;
}