//
// Created by thomas on 20/05/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_rr.h"
#include "../prove_stuffs/prove.h"
#include "../prove_stuffs/prove_helpers.h"

/* starting point */
uint64_t encode_cluster_list(args_t *args UNUSED);

PROOF_INSTS(
        uint16_t nondet_get_u16__verif(void);
        uint8_t nondet_get_buf__verif(void);

        struct path_attribute *get_attr() {
            struct path_attribute *p_attr;
            uint16_t len;

            len = nondet_get_u16__verif();
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


#define TIDYING() \
PROOF_INSTS( do { \
    if (attribute) free(attribute); \
    if (to_info) free(to_info);     \
    if (attr_buf) free(attr_buf);\
} while(0);)

#define KEY_MEM_EXPORT 598
#define SIZE_MEM_EXPORT 6144

static __always_inline void *get_mem(void) {
    void *mem;
    mem = ctx_shmget(KEY_MEM_EXPORT);
    if (mem) return mem;

    mem = ctx_shmnew(KEY_MEM_EXPORT, SIZE_MEM_EXPORT);
    if (!mem) {
        ebpf_print("[FATAL !] Unable to create extended memory !\n");
        return NULL;
    }
    return mem;
}

uint64_t encode_cluster_list(args_t *args UNUSED) {
    uint32_t counter = 0;
    uint16_t tot_len = 0;
    unsigned int i;
    int nb_peer;
    unsigned char *extra_space;
    unsigned char *attr_buf;
    unsigned int length_clist;

    struct ubpf_peer_info *to_info = NULL;
    struct path_attribute *cluster_list_attr = NULL;
    uint32_t *cluster_list;

    to_info = get_peer_info(&nb_peer);

    if (!to_info) {
        ebpf_print("Can't get src peer info\n");
        TIDYING()
        next();
        return 0;
    }

    if (to_info->peer_type != IBGP_SESSION) {
        ebpf_print("This is not an ibgp session\n");
        next();
    }

    cluster_list_attr = get_attr_from_code(CLUSTER_LIST_ATTR_ID);

    if (!cluster_list_attr) {
        TIDYING()
        next();
        return 0;
    }

    tot_len += 2; // Type hdr

    length_clist = cluster_list_attr->length;
    tot_len += length_clist < 256 ? 1 : 2;
    tot_len += length_clist;


    extra_space = get_mem();
    if (!extra_space) {
        ebpf_print("Unable to get extra space\n");
        next();
        return 0;
    }

    /*if (attribute->length >= UINT16_MAX - 2 - (attribute->length < 256 ? 1 : 2)) {
        TIDYING();
        return 0;
    }*/


    CREATE_BUFFER(attr_buf, tot_len);
    attr_buf = extra_space;

    attr_buf[counter++] = cluster_list_attr->flags;
    attr_buf[counter++] = cluster_list_attr->code;

    if (length_clist < 256) attr_buf[counter++] = length_clist;
    else {
        unsigned int hto_length = ebpf_htons(length_clist);
        memcpy(&attr_buf[counter], &hto_length, 2);
        //*(uint16_t *)(&attr_buf[counter]) = ebpf_htons(length_clist);
        counter += 2;
    }


    cluster_list = (uint32_t *) cluster_list_attr->data;
    for (i = 0; i < cluster_list_attr->length / 4; i++) {
        *((uint32_t *) (attr_buf + counter)) = ebpf_htonl(cluster_list[i]);
        counter += 4;
    }


    if (counter != tot_len) {
        ebpf_print("Size missmatch counter %d totlen %d\n", LOG_U32(counter), LOG_U32(tot_len));
        TIDYING();
        next();
        return 0;
    }

    //CHECK_ATTR(attr_buf);

    CHECK_BUFFER(attr_buf, counter);
    if (write_to_buffer(attr_buf, counter) == -1) {
        ebpf_print("Write failed\n");
        TIDYING();
        next();
        return 0;
    }
    TIDYING();
    next();
    return counter;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = encode_cluster_list(&args);
            return ret_val;
        }
)
