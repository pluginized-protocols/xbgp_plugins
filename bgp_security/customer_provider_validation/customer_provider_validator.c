//
// Created by thomas on 3/06/20.
//
#ifdef PROVERS
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_security.h"
#include "../byte_manip.h"
#include "../prove_stuffs/prove.h"
#else
#include "../../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../common_security.h"
#include "../../byte_manip.h"
#include "../../prove_stuffs/prove.h"
#endif

#define SESSION_MY_PROVIDER 1
#define SESSION_MY_CUSTOMER 2
#define SESSION_MY_PEER 3
#define SESSION_MY_RS 4
#define SESSION_MY_RS_CLIENT 5

#define MAX_ITERATION INT32_MAX


// T2 doesn't like variadic functions
#ifdef PROVERS_T2
#define ubpf_sprintf(...)

#define ebpf_print(...)
#endif

/**
 *  Starting point of the BPF program
 */
uint64_t customer_provider_validator(args_t *args UNUSED);

struct global_info info;

PROOF_INSTS(
        #define NEXT_RETURN_VALUE PLUGIN_FILTER_UNKNOWN

        uint8_t *nondet_get_buf__verif();
        struct ubpf_peer_info *nondet_get_pinfo__verif();
        uint16_t nondet_get_u16__verif();
        uint8_t nondet_u8();

        struct ubpf_peer_info *get_peer_info(int *nb_peers) {
            unsigned char *data;
            struct ubpf_peer_info *pinfo;
            data = malloc(2*sizeof(*pinfo));
            if (!data) return NULL;
            pinfo = (struct ubpf_peer_info *) data;
            pinfo->peer_type = nondet_u8();
            pinfo->local_bgp_session = (struct ubpf_peer_info *) (data + sizeof(*pinfo));
            return pinfo;
        }

        struct ubpf_peer_info *get_src_peer_info() {
            int i = 1;
            return get_peer_info(&i);
        }


        struct path_attribute *get_attr_from_code(uint8_t code) {
            struct path_attribute *p_attr;
            uint8_t l = nondet_u8();
            p_attr = malloc(sizeof(struct path_attribute) + l);

            switch (code) {
                case AS_PATH_ATTR_ID:
                    p_attr->code = AS_PATH_ATTR_ID;
                    p_attr->flags = ATTR_TRANSITIVE;
                    p_attr->length = l;
                    return p_attr;
                    break;
                default:
                    //p_assert(0);
                    return NULL;
            }
            return NULL;
        }
)

/*
 *  0 if not valid
 *  1 if valid
 * -1 if unknown
 * -2 if fail;
 */
static __always_inline int valid_pair(uint32_t asn, uint32_t prov) {
    char customer_as_str[12];
    uint32_t provider_as;
    int i;
    struct global_info prov_info;
    struct global_info cust_info;

    memset(customer_as_str, 0, 12);
    ubpf_sprintf(customer_as_str, 10, "%d", asn);

    if (get_extra_info_dict(&info, customer_as_str, &cust_info) != 0) return -1;

    for (i = 0; i < MAX_ITERATION; i++) {
        if (get_extra_info_lst_idx(&cust_info, i, &prov_info) != 0) return 0;
        if (get_extra_info_value(&prov_info, &provider_as, sizeof(provider_as)) != 0) {
            ebpf_print("Unable to copy provider as\n");
            return -2;
        }

        if (provider_as == prov) return 1;
    }

    return 0;
}

static __always_inline int get_session_relation(uint32_t upstream_as) {

    uint64_t session_type;
    char as_str[15];
    struct global_info info_;
    struct global_info session_info;
    struct global_info neighbor_relation;

    memset(as_str, 0, 15);
    ubpf_sprintf(as_str, 14, "%d", upstream_as);

    if (get_extra_info("neighbors", &info_) != 0) return -1;
    if (get_extra_info_dict(&info_, as_str, &session_info) != 0) return -1;
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

static __always_inline int from_customer_check(uint32_t my_as, struct path_attribute *attr) {
    if (!attr || attr->code != AS_PATH_ATTR_CODE) return -1;

    int current_res = 1;

    const uint8_t * const pos = attr->data;

    unsigned int bytes = 0;
    unsigned int tot_length = attr->length;

    uint32_t prev_as = my_as;
    uint32_t curr_as;

    PROOF_T2_INSTS(unsigned int trap = 0;)

    while (bytes < tot_length PROOF_T2_INSTS(&& trap < 4096)) {
        PROOF_T2_INSTS(trap += 6;)
        unsigned char type = pos[bytes++];
        unsigned char len = pos[bytes++];

        if (!len)
            break;

        if (len > 255) {
            break; // should never happen but just in case for provers
        }

        if (tot_length - bytes <= len * 4) {
            break;
        }

        switch (type) {
            case AS_PATH_SET:
            case AS_PATH_CONFED_SET:
                return -1;

            case AS_PATH_SEQUENCE:
            case AS_PATH_CONFED_SEQUENCE:
                curr_as = get_u32(pos + AS_N_SIZE * (len - 1));

                int a = valid_pair(prev_as, curr_as);

                switch (a) {
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

        bytes += AS_N_SIZE * len;
    }

    return current_res;
}

static __always_inline  int from_provider_check(uint32_t my_as, struct path_attribute *attr) {
    if (!attr || attr->code != AS_PATH_ATTR_CODE) return -1;

#define VALID_1 1
#define UNK_1 2
#define VALID_2 3
#define UNK_2 4

    int current_state = VALID_1;
    int curr_check;

    const uint8_t * const pos = attr->data;

    unsigned int bytes = 0;
    unsigned int tot_length = attr->length;

    PROOF_T2_INSTS(unsigned int trap = 0;)

#ifdef PROVERS_T2
    unsigned long prev_as = my_as;
    unsigned long curr_as;
#else
    uint32_t prev_as = my_as;
    uint32_t curr_as;
#endif

    while (bytes < tot_length PROOF_T2_INSTS(&& trap < 4096)) {
        PROOF_T2_INSTS(trap += 6;)
        unsigned char type = pos[bytes++];
        unsigned char len = pos[bytes++];

        if (!len) {
            return -1; // malformed as_seg
        }

        if (len > 255) {
            return -1; // should never happen but just in case for provers
        }

        if (tot_length - bytes <= len * 4) {
            return -1;
        }

        switch (type) {
            case AS_PATH_SET:
            case AS_PATH_CONFED_SET:
                return -1;

            case AS_PATH_SEQUENCE:
            case AS_PATH_CONFED_SEQUENCE:
                curr_as = get_u32(pos + AS_N_SIZE * (len - 1));
                curr_check = valid_pair(prev_as, curr_as);

                if (current_state == VALID_1) {
                    if (curr_check == -1) {
                        current_state = UNK_1;
                    } else if (curr_check == 0) {
                        current_state = VALID_2;
                    } else if (curr_check == -2) {
                        return -1;
                    }

                } else if (current_state == UNK_1) {
                    if (curr_check == 0) {
                        current_state = UNK_2;
                    } else if (curr_check == -2) {
                        return -1;
                    }

                } else if (current_state == VALID_2) {
                    if (curr_check == 0) {
                        return 0;
                    } else if (curr_check == -1) {
                        current_state = UNK_2;
                    } else if (curr_check == -2) {
                        return -1;
                    }

                } else if (current_state == UNK_2) {
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

        bytes += AS_N_SIZE * len;
    }

    return current_state == VALID_1 || current_state == VALID_2 ? 1 : -1;
}

#define TIDYING() \
PROOF_INSTS(do {            \
    if (attr) free(attr); \
    if (peer) free(peer); \
} while(0))

uint64_t customer_provider_validator(args_t *args UNUSED) {

    struct path_attribute *attr;
    uint32_t my_as, from_as;
    int ret_val;

    attr = get_attr_from_code(AS_PATH_ATTR_CODE);

    struct ubpf_peer_info *peer = get_src_peer_info();
    if (!attr || !peer){
        TIDYING();
        return FAIL;
    }

    from_as = peer->as;
    my_as = peer->local_bgp_session->as;


    if (get_extra_info("cust-prov", &info) != 0){
        TIDYING();
        return PLUGIN_FILTER_UNKNOWN;
    }

    switch (get_session_relation(from_as)) {
        case SESSION_MY_PROVIDER:
            ret_val = from_provider_check(my_as, attr);
            break;
        case SESSION_MY_CUSTOMER:
            ret_val = from_customer_check(my_as, attr);
            break;
        default:
            ret_val = -1;
            TIDYING();
            next();
    }

    if (ret_val == 0) return PLUGIN_FILTER_REJECT;
    TIDYING();
    next();
    return PLUGIN_FILTER_REJECT;
}


PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = customer_provider_validator(&args);
            PROOF_SEAHORN_INSTS(
                    RET_VAL_FILTERS_CHECK(ret_val);
            )

            return ret_val;
        }
)