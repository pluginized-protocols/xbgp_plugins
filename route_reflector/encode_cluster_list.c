//
// Created by thomas on 20/05/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_rr.h"
#include "../prove_stuffs/prove.h"

/* starting point */
uint64_t encode_cluster_list(args_t *args UNUSED);

PROOF_INSTS(
        uint16_t nondet_get_u16__verif(void);
        uint8_t nondet_get_buf__verif(void);

        struct path_attribute *get_attr() {
            struct path_attribute *p_attr;
            uint16_t len;

            len =  nondet_get_u16__verif();
            p_assume(len % 4 == 0);
            //p_assume(len <= 4096);

            p_attr = malloc(sizeof(*p_attr) + len);
            if (!p_attr) return NULL;

            PROOF_CBMC_INSTS(__CPROVER_havoc_object(p_attr);)

            p_attr->code = CLUSTER_LIST;
            p_attr->flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;
            p_attr->length = len;

            return p_attr;
        }

        struct ubpf_peer_info *get_src_peer_info() {
            struct ubpf_peer_info *pf;

            pf = malloc(sizeof(*pf));
            if (!pf) return NULL;

            pf->peer_type = IBGP_SESSION;
            return pf;
        }

        struct ubpf_peer_info *get_peer_info(int *nb_peers) {
            return get_src_peer_info();
        }

#define NEXT_RETURN_VALUE FAIL;
)


#define TIDYING() PROOF_INSTS( do { \
    if (attribute) free(attribute); \
    if (to_info) free(to_info);     \
    if (attr_buf) free(attr_buf);\
} while(0);)

uint64_t encode_cluster_list(args_t *args UNUSED) {

    uint32_t counter = 0;
    uint8_t *attr_buf = NULL;
    uint16_t tot_len = 0;
    uint32_t *cluster_list;
    int i;
    int nb_peer;

    struct ubpf_peer_info *to_info = NULL;
    struct path_attribute *attribute;
    attribute = get_attr();

    if (!attribute) {
        ebpf_print("No attribute ?\n");
        TIDYING();
        return 0;
    }

    to_info = get_peer_info(&nb_peer);

    if (!to_info) {
        ebpf_print("Can't get src and peer info\n");
        TIDYING()
        return 0;
    }

    if (to_info->peer_type != IBGP_SESSION) {
        ebpf_print("This is not an ibgp session\n");
        next();
    }

    if (attribute->code != CLUSTER_LIST) {
        TIDYING();
        next();
    }

    if (attribute->length >= UINT16_MAX - 2 - (attribute->length < 256 ? 1 : 2)) {
        TIDYING();
        return 0;
    }

    tot_len += 2; // Type hdr
    tot_len += attribute->length < 256 ? 1 : 2; // Length hdr
    tot_len += attribute->length;

    attr_buf = ctx_calloc(1, tot_len);
    if (!attr_buf) {
        TIDYING();
        return 0;
    }

    attr_buf[counter++] = attribute->flags;
    attr_buf[counter++] = attribute->code;

    if (attribute->length < 256) attr_buf[counter++] = (uint8_t) attribute->length;
    else {
        memcpy(attr_buf + counter, &attribute->length, sizeof(attribute->length));
        counter += 2;
    }

    cluster_list = (uint32_t *) attribute->data;
    for (i = 0; i < attribute->length / 4; i++) {
        *((uint32_t *) (attr_buf + counter)) = ebpf_htonl(cluster_list[i]);
        counter += 4;
    }

    if (counter != tot_len) {
        ebpf_print("Size missmatch counter %d totlen %d\n", LOG_U32(counter), LOG_U32(tot_len));
        TIDYING();
        return 0;
    }

    PROOF_SEAHORN_INSTS(
            BUF_CHECK_ORIGINATOR(attr_buf);
    )

    if (write_to_buffer(attr_buf, counter) == -1) {
        ebpf_print("Write failed\n");
        TIDYING();
        return 0;
    }
    TIDYING();
    return counter;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = encode_cluster_list(&args);
            return ret_val;
        }
)
