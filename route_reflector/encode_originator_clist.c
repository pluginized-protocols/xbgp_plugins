//
// Created by thomas on 4/03/22.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../prove_stuffs/prove.h"

#define KEY_MEM_EXPORT 123
#define SIZE_MEM_EXPORT 6144

#define OFFSET_ORIGINATOR 0
#define OFFSET_CLUSTER_LIST 7

#define ORIGINATOR_ATTR_LEN 4

PROOF_INSTS(

        uint16_t nondet_len();
        uint8_t nondet_u8();
        struct ubpf_peer_info *get_src_peer_info() {
            struct ubpf_peer_info *pf;

            pf = malloc(2*sizeof(struct ubpf_peer_info));
            if (!pf) return NULL;

            pf->local_bgp_session = &(pf[1]);

            pf->peer_type = nondet_u8();
            return pf;
        }

        struct ubpf_peer_info *get_peer_info(int *nb_peers) {
            return get_src_peer_info();
        }

        struct path_attribute *get_attr_from_code(uint8_t code) {
            struct path_attribute *obj;
            uint16_t len;
            switch(code){
                case ORIGINATOR_ID_ATTR_ID:
                    len = sizeof(uint32_t);
                    break;
                case CLUSTER_LIST_ATTR_ID:
                    len = nondet_len() / 16 * 4;
                    break;
            }
            obj = malloc(sizeof(struct path_attribute) + len);
            if (obj == NULL) return NULL;
            obj->length = len;
            return obj;
        }
)

/* plugin entry point */
uint64_t encode_originator_clist(void);
#ifdef PROVERS_T2
static __always_inline void *get_mem(void) {
    return malloc(100000);
}
#else
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
#endif

#define TIDYING() \
PROOF_INSTS(do {            \
    if (dst_peer) free(dst_peer);     \
    if (src_peer) free(src_peer); \
    if (originator_id) free(originator_id); \
    if (cluster_list) free(cluster_list); \
} while(0))

uint64_t encode_originator_clist(void) {
    int nb_peer;
    unsigned int i;
    struct ubpf_peer_info *src_peer = NULL;
    struct ubpf_peer_info *dst_peer = NULL;

    struct path_attribute *originator_id = NULL;
    struct path_attribute *cluster_list = NULL;

    unsigned char *extra_mem;
    unsigned char *originator;
    unsigned char *clist;

    unsigned int offset_or = 0;
    unsigned int offset_cl = 0;
    unsigned int clist_len;
    unsigned int total_offset;

    extra_mem = get_mem();
    if (!extra_mem) {
        TIDYING();
        return 0;
    }

    dst_peer = get_peer_info(&nb_peer);
    if (!dst_peer) {
        ebpf_print("Unable to get dst peer info\n");
        TIDYING();
        return 0;
    }

    if (dst_peer->peer_type != IBGP_SESSION) {
        ebpf_print("Destination peer is not iBGP\n");
        TIDYING();
        return 0;
    }

    originator_id = get_attr_from_code(ORIGINATOR_ID_ATTR_ID);
    cluster_list = get_attr_from_code(CLUSTER_LIST_ATTR_ID);

    /* first. craft originator id */
    originator = &extra_mem[OFFSET_ORIGINATOR];

    originator[offset_or++] = ATTR_OPTIONAL;
    originator[offset_or++] = ORIGINATOR_ID_ATTR_ID;
    originator[offset_or++] = ORIGINATOR_ATTR_LEN;

    if (originator_id) {
        memcpy(originator + offset_or, originator_id->data, sizeof(uint32_t));
    } else {
        src_peer = get_src_peer_info();
        if (!src_peer) {
            ebpf_print("Unable to get src peer info\n");
            TIDYING();
            return 0;
        }
        *(uint32_t *) (&originator[offset_or]) = ebpf_htonl(src_peer->router_id);
    }
    offset_or += 4;

    if (offset_or != OFFSET_CLUSTER_LIST) {
        ebpf_print("Malformed ORIGINATOR_ID\n");
        TIDYING();
        return 0;
    }

    /* next. craft cluster list */
    clist = &extra_mem[OFFSET_CLUSTER_LIST];

    clist[offset_cl++] = ATTR_OPTIONAL;
    clist[offset_cl++] = CLUSTER_LIST_ATTR_ID;

    clist_len = 4;
    if (cluster_list) {
        clist_len += cluster_list->length;
    }

    if (clist_len < 256) {
        clist[offset_cl++] = clist_len;
    } else {
        *(uint16_t *) (&clist[offset_cl]) = ebpf_htons(clist_len);
        offset_cl += 2;
        clist[0] |= ATTR_EXT_LEN;
    }

    /* prepend our router_id */
    *(uint32_t *) (&clist[offset_cl]) = ebpf_htonl(dst_peer->local_bgp_session->router_id);
    offset_cl += 4;
    if (cluster_list) {
        for (i = 0; i < cluster_list->length / 4; i++) {
            *(uint32_t *) (&clist[offset_cl]) = ebpf_htonl(((uint32_t *)(cluster_list->data))[i]);
            offset_cl += 4;
        }
    }

    total_offset = offset_or + offset_cl;
    if (write_to_buffer(extra_mem, total_offset) != 0) {
        ebpf_print("Unable to send attribute to the wire\n");
        TIDYING();
        return 0;
    }
    TIDYING();
    return total_offset;
}

PROOF_INSTS(
        int main(void) {
            uint64_t ret_val;
            ctx_shmnew(KEY_MEM_EXPORT, SIZE_MEM_EXPORT);

            ret_val = encode_originator_clist();

            ctx_shmrm(KEY_MEM_EXPORT);
            return ret_val >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
        }
)