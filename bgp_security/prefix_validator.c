//
// Created by thomas on 2/06/20.
//

#include "../../public_bpf.h"
#include "../../ubpf_prefix.h"
#include "ubpf_api.h"
#include "common_security.h"
#include "../byte_manip.h"

#define AS_PATH_SET		1	/* Types of path segments */
#define AS_PATH_SEQUENCE	2
#define AS_PATH_CONFED_SEQUENCE	3
#define AS_PATH_CONFED_SET	4
int __always_inline
as_path_get_last(struct path_attribute *attr, uint32_t *orig_as)
{
    const uint8_t *pos = attr->data;
    const uint8_t *end = pos + attr->len;
    int found = 0;
    uint32_t val = 0;

    while (pos < end)
    {
        uint type = pos[0];
        uint len  = pos[1];
        pos += 2;

        if (!len)
            continue;

        switch (type)
        {
            case AS_PATH_SET:
            case AS_PATH_CONFED_SET:
                found = 0;
                break;

            case AS_PATH_SEQUENCE:
            case AS_PATH_CONFED_SEQUENCE:
                val = get_u32(pos + 4 * (len - 1));
                found = 1;
                break;
            default:
                return 0;
        }

        pos += 4 * len;
    }

    if (found)
        *orig_as = val;
    return found;
}



void *memset(void *s, int c, size_t n);

uint64_t prefix_validator(bpf_full_args_t *args UNUSED) {

    int i;
    int prefix_exists = 0;
    struct global_info info, list_vrp, curr_vrp;
    struct global_info current_len, current_max_len, current_originator_as;
    uint64_t vrp_as, vrp_len, vrp_max_len;
    union ubpf_prefix *pfx_to_validate;
    uint16_t prefix_len_to_val;
    struct path_attribute *as_path;
    uint32_t orig_as;

    char str_ip[45];
    memset(str_ip, 0, 45);

    as_path = get_attr_from_code(AS_PATH_ATTR_CODE);
    pfx_to_validate = get_prefix();
    if (!as_path || !pfx_to_validate) {
        ebpf_print("Unable to allocate memory\n");
        return FAIL;
    }

    prefix_len_to_val = pfx_to_validate->family == AF_INET ? pfx_to_validate->ip4_pfx.prefix_len
                                                           : pfx_to_validate->ip6_pfx.prefix_len;

    if (get_extra_info("allowed_prefixes", &info) != 0) {
        ebpf_print("No extra info ?\n");
        next();
    }

    if (ebpf_inet_ntop(pfx_to_validate, str_ip, 44) != 0) {
        ebpf_print("Conversion ip to str error");
        return FAIL;
    }

    if (get_extra_info_dict(&info, str_ip, &list_vrp) != 0) {
        // We don't know...
        next();
    }

    for (i = 0;; i++) {

        if (get_extra_info_lst_idx(&list_vrp, i, &curr_vrp) != 0) {

            if (prefix_exists) return PLUGIN_FILTER_REJECT;
            else next();
            //ebpf_print("Announce rejected\n");
        }

        if (get_extra_info_lst_idx(&curr_vrp, 0, &current_len) != 0) {
            ebpf_print("FAIL current len VRP");
            return FAIL;
        }
        if (get_extra_info_lst_idx(&curr_vrp, 1, &current_max_len) != 0) {
            ebpf_print("FAIL current max len VRP");
            return FAIL;
        }
        if (get_extra_info_lst_idx(&curr_vrp, 2, &current_originator_as) != 0) {
            ebpf_print("FAIL current originator as VRP");
            return FAIL;
        }
        if (get_extra_info_value(&current_len, &vrp_len, sizeof(vrp_len)) != 0) {
            ebpf_print("FAIL cannot get vrp_len");
            return FAIL;
        }
        if (get_extra_info_value(&current_max_len, &vrp_max_len, sizeof(vrp_max_len)) != 0) {
            ebpf_print("FAIL cannot get vrp_max_len");
            return FAIL;
        }
        if (get_extra_info_value(&current_originator_as, &vrp_as, sizeof(vrp_as)) != 0) {
            ebpf_print("FAIL cannot get vrp_len");
            return FAIL;
        }

        if (vrp_len <= prefix_len_to_val) { // covered
            prefix_exists = 1;

            if (!as_path_get_last(as_path, &orig_as)){
                return PLUGIN_FILTER_REJECT;
            }

            if (prefix_len_to_val <= vrp_max_len) {
                if (vrp_as == orig_as){
                    next(); // valid prefix !
                }
            }
        }
    }
}