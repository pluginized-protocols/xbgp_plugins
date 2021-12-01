//
// Created by thomas on 20/05/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include <bytecode_public.h>
#include "common_rr.h"
#include "../prove_stuffs/prove.h"

/* starting point */
uint64_t encode_cluster_list(args_t *args UNUSED);

PROOF_INSTS(
        uint16_t nondet_get_u16__verif();
        uint8_t nondet_get_buf__verif();
        struct ubpf_peer_info *nondet_gpi__verif();

        struct path_attribute *get_attr() {
            struct path_attribute *p_attr;
            p_attr = malloc(sizeof(*p_attr));
            if (!p_attr) return NULL;

            p_attr->code = CLUSTER_LIST;
            p_attr->flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;
            p_attr->length = nondet_get_u16__verif();
            memcpy(p_attr->data, nondet_get_buf__verif(), 8);

            return p_attr;
        }

        struct ubpf_peer_info *get_src_peer_info() {
            struct ubpf_peer_info *pf = nondet_gpi__verif();
            pf->peer_type = IBGP_SESSION;
        }
)


uint64_t encode_cluster_list(args_t *args UNUSED) {

    uint32_t counter = 0;
    uint8_t *attr_buf;
    uint16_t tot_len = 0;
    uint32_t *cluster_list;
    int i;
    int nb_peer;

    struct path_attribute *attribute;
    attribute = get_attr();

    if (!attribute) {
        ebpf_print("No attribute ?\n");
        return 0;
    }

    struct ubpf_peer_info *to_info;
    to_info = get_peer_info(&nb_peer);

    if (!to_info) {
        ebpf_print("Can't get src and peer info\n");
        return 0;
    }

    if (to_info->peer_type != IBGP_SESSION) {
        ebpf_print("This is not an ibgp session\n");
        next();
    }

    if (attribute->code != CLUSTER_LIST) next();

    tot_len += 2; // Type hdr
    tot_len += attribute->length < 256 ? 1 : 2; // Length hdr
    tot_len += attribute->length;

    attr_buf = ctx_calloc(1, tot_len);
    if (!attr_buf) return 0;

    attr_buf[counter++] = attribute->flags;
    attr_buf[counter++] = attribute->code;

    if (attribute->length < 256) attr_buf[counter++] = (uint8_t) attribute->length;
    else {
        attr_buf[counter] = attribute->length;
        counter += 2;
    }

    cluster_list = (uint32_t *) attribute->data;
    for (i = 0; i < attribute->length / 4; i++) {
        *((uint32_t *) (attr_buf + counter)) = ebpf_htonl(cluster_list[i]);
        counter += 4;
    }

    if (counter != tot_len) {
        ebpf_print("Size missmatch counter %d totlen %d\n", counter, tot_len);
        return 0;
    }

    PROOF_SEAHORN_INSTS(
            BUF_CHECK_ORIGINATOR(attr_buf);
    )

    if (write_to_buffer(attr_buf, counter) == -1) {
        ebpf_print("Write failed\n");
        return 0;
    }
    return counter;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = decode_cluster_list();
            return ret_val;
        }
)
