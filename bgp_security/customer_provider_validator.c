//
// Created by thomas on 3/06/20.
//

#include "../byte_manip.h"
#include "../../public_bpf.h"
#include "../../ubpf_prefix.h"
#include "ubpf_api.h"
#include "common_security.h"

#define SESSION_MY_PROVIDER 1
#define SESSION_MY_CUSTOMER 2
#define SESSION_MY_PEER 3
#define SESSION_MY_RS 4
#define SESSION_MY_RS_CLIENT 5

/* only for static arrays !!! */
void *memset(void *s, int c, size_t n);

struct global_info info;

/*
 *  0 if not valid
 *  1 if valid
 * -1 if unknown
 * -2 if fail;
 */
int __always_inline valid_pair(uint32_t asn, uint32_t prov) {
    char customer_as_str[12];
    uint32_t provider_as;
    int i;
    struct global_info prov_info;
    struct global_info cust_info;

    memset(customer_as_str, 0, 12);
    ubpf_sprintf(customer_as_str, 10, "%d", asn);

    if (get_extra_info_dict(&info, customer_as_str, &cust_info) != 0) return -1;

    for (i = 0; ; i++) {
        if (get_extra_info_lst_idx(&cust_info, i, &prov_info) != 0) return 0;
        if (get_extra_info_value(&prov_info, &provider_as, sizeof(provider_as)) != 0) {
            ebpf_print("Unable to copy provider as\n");
            return -2;
        }

        if (provider_as == prov) return 1;
    }

    return 0;
}

int __always_inline get_session_relation(uint32_t upstream_as) {

    uint64_t session_type;
    char as_str[15];
    struct global_info info;
    struct global_info session_info;
    struct global_info neighbor_relation;

    memset(as_str, 0, 15);
    ubpf_sprintf(as_str, 14, "%d", upstream_as);

    if (get_extra_info("neighbors", &info) != 0) return -1;
    if (get_extra_info_dict(&info, as_str, &session_info) != 0) return -1;
    if (get_extra_info_dict(&session_info, "session_type", &neighbor_relation) != 0) return -1;
    if (get_extra_info_value(&neighbor_relation, &session_type, sizeof(session_type)) != 0) return -1;

    switch (session_type) {
        case SESSION_MY_CUSTOMER:
        case SESSION_MY_PEER:
        case SESSION_MY_PROVIDER:
        case SESSION_MY_RS:
        case SESSION_MY_RS_CLIENT:
            return session_type;
        default:
            return -1;
    }
}

int __always_inline from_customer_check(uint32_t my_as, struct path_attribute *attr) {
    if (!attr || attr->code != AS_PATH_ATTR_CODE) return -1;

    int current_res = 1;

    const uint8_t *pos = attr->data;
    const uint8_t *end = pos + attr->len;

    uint32_t prev_as = my_as;
    uint32_t curr_as;

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
                return -1;

            case AS_PATH_SEQUENCE:
            case AS_PATH_CONFED_SEQUENCE:
                curr_as = get_u32(pos + AS_N_SIZE * (len - 1));

                switch (valid_pair(prev_as, curr_as)) {
                    case -1:
                        current_res = -1;
                        break;
                    case 0:
                        return 0;
                    case -2:
                        return -1;
                }
                prev_as = curr_as;
                break;

            default:
                return -1;
        }

        pos += AS_N_SIZE * len;
    }

    return current_res;
}

int __always_inline from_provider_check(uint32_t my_as, struct path_attribute *attr) {
    if (!attr || attr->code != AS_PATH_ATTR_CODE) return -1;

#define VALID_1 1
#define UNK_1 2
#define VALID_2 3
#define UNK_2 4

    int current_state = VALID_1;
    int curr_check;

    const uint8_t *pos = attr->data;
    const uint8_t *end = pos + attr->len;

    uint32_t prev_as = my_as;
    uint32_t curr_as;

    while (pos < end) {
        uint type = pos[0];
        uint len  = pos[1];
        pos += 2;

        if (!len)
            continue;

        switch (type) {
            case AS_PATH_SET:
            case AS_PATH_CONFED_SET:
                return -1;

            case AS_PATH_SEQUENCE:
            case AS_PATH_CONFED_SEQUENCE:
                curr_as = get_u32(pos + AS_N_SIZE * (len - 1));

                if (current_state == VALID_1) {
                    curr_check = valid_pair(prev_as, curr_as);
                    if (curr_check == -1) {
                        current_state = UNK_1;
                    } else if (curr_check == 0) {
                        current_state = VALID_2;
                    }  else if (curr_check == -2) {
                        return -1;
                    }

                } else if (current_state == UNK_1) {
                    curr_check = valid_pair(prev_as, curr_as);
                    if (curr_check == 0) {
                        current_state = UNK_2;
                    } else if (curr_check == -2) {
                        return -1;
                    }

                } else if (current_state == VALID_2) {
                    curr_check = valid_pair(curr_as, prev_as);
                    if (curr_check == 0) {
                        return 0;
                    } else if (curr_check == -1) {
                        current_state = UNK_2;
                    } else if (curr_check == -2) {
                        return -1;
                    }

                } else if (current_state == UNK_2) {
                    curr_check = valid_pair(curr_as, prev_as);
                    if (curr_check == 0) {
                        return 0;
                    } else if (curr_check == -2) {
                        return -1;
                    }
                }

                prev_as = curr_as;
                break;

            default:
                return -1;
        }

        pos += AS_N_SIZE * len;
    }

    return current_state == VALID_1 || current_state == VALID_2 ? 1 : -1;
}

uint64_t customer_provider(bpf_full_args_t *args UNUSED) {

    struct path_attribute *attr;
    uint32_t my_as, from_as;
    int ret_val;

    attr = get_attr_from_code(AS_PATH_ATTR_CODE);

    struct ubpf_peer_info *peer = get_src_peer_info();
    if (!attr || !peer) return FAIL;

    from_as = peer->as;
    my_as = peer->local_bgp_session->as;


    if(get_extra_info("cust-prov", &info) != 0) return -1;

    switch (get_session_relation(from_as)) {
        case SESSION_MY_PROVIDER:
            ret_val = from_provider_check(my_as, attr);
            break;
        case SESSION_MY_CUSTOMER:
            ret_val = from_customer_check(my_as, attr);
            break;
        default:
            ret_val = -1;
            next();
    }

    if (ret_val == 0) return PLUGIN_FILTER_REJECT;

    next();
    return PLUGIN_FILTER_REJECT;
}