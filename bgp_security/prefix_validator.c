//
// Created by thomas on 2/06/20.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include <bytecode_public.h>
#include <sys/socket.h>
#include "common_security.h"
#include "../byte_manip.h"

#define AS_PATH_SET		1	/* Types of path segments */
#define AS_PATH_SEQUENCE	2
#define AS_PATH_CONFED_SEQUENCE	3
#define AS_PATH_CONFED_SET	4

#ifdef PROVERS

struct path_attribute *get_attr_from_code(uint8_t code) {
    struct path_attribute *attr;
    if (code != AS_PATH_ATTR_CODE) {
        return NULL;
    }

    attr = malloc(sizeof(*attr) + 32);
    if (!attr) return NULL;

    attr->code = AS_PATH_ATTR_CODE;
    attr->flags = ATTR_TRANSITIVE;
    attr->length = 32;
    // leave trash data for data attribute

    return attr;
}

struct ubpf_prefix *get_prefix() {
    struct ubpf_prefix *pfx;
    pfx = malloc(sizeof(*pfx));
    if (!pfx) return NULL;

    pfx->afi = XBGP_AFI_IPV4;
    pfx->safi = XBGP_SAFI_UNICAST;
    pfx->prefixlen = 16;
    *(uint32_t *)pfx->u = 16820416; // 192.168.0.1

    return pfx;
}

#endif


int __always_inline
as_path_get_last(struct path_attribute *attr, uint32_t *orig_as)
{
    const uint8_t *pos = attr->data;
    const uint8_t *end = pos + attr->length;
    int found = 0;
    uint32_t val = 0;

    while (pos < end)
    {
        uint type = pos[0];
        uint len  = pos[1];
        pos += 2;

        if (len <= 0)
            continue;

        switch (type) {
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

uint64_t prefix_validator(args_t *args UNUSED) {

    int i;
    int prefix_exists = 0;
    struct global_info info, list_vrp, curr_vrp;
    struct global_info current_len, current_max_len, current_originator_as;
    uint64_t vrp_as, vrp_len, vrp_max_len;
    struct ubpf_prefix *pfx_to_validate;
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

    prefix_len_to_val = pfx_to_validate->prefixlen;

    if (get_extra_info("allowed_prefixes", &info) != 0) {
        ebpf_print("No extra info ?\n");
        next();
    }

    if (ebpf_inet_ntop(pfx_to_validate->u, iana_afi_to_af(pfx_to_validate->afi), str_ip, 44) != 0) {
        ebpf_print("Conversion ip to str error");
        return FAIL;
    }

    if (get_extra_info_dict(&info, str_ip, &list_vrp) != 0) {
        // We don't know...
        next();
    }

    // get the last as
    if (!as_path_get_last(as_path, &orig_as)){
        return PLUGIN_FILTER_REJECT;
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

            if (prefix_len_to_val <= vrp_max_len) {
                if (vrp_as == orig_as){
                    next(); // valid prefix !
                }
            }
        }
    }
}