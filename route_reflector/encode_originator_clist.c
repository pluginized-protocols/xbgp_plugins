//
// Created by thomas on 4/03/22.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"

#define KEY_MEM_EXPORT 123
#define SIZE_MEM_EXPORT 6144

#define OFFSET_ORIGINATOR 0
#define OFFSET_CLUSTER_LIST 7

#define ORIGINATOR_ATTR_LEN 4

/* plugin entry point */
uint64_t encode_originator_clist(void) ;

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

uint64_t encode_originator_clist(void) {
    int nb_peer;
    unsigned int i;
    struct ubpf_peer_info *src_peer;
    struct ubpf_peer_info *dst_peer;

    struct path_attribute *originator_id;
    struct path_attribute *cluster_list;

    unsigned char *extra_mem;
    unsigned char *originator;
    unsigned char *clist;

    unsigned int offset_or = 0;
    unsigned int offset_cl = 0;
    unsigned int clist_len;
    unsigned int total_offset;

    extra_mem = get_mem();
    if (!extra_mem) {
        return 0;
    }

    dst_peer = get_peer_info(&nb_peer);
    if (!dst_peer) {
        ebpf_print("Unable to get dst peer info\n");
        return 0;
    }

    if (dst_peer->peer_type != IBGP_SESSION) {
        ebpf_print("Destination peer is not iBGP\n");
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
            return 0;
        }
        *(uint32_t *) (&originator[offset_or]) = ebpf_htonl(src_peer->router_id);
    }
    offset_or += 4;

    if (offset_or != OFFSET_CLUSTER_LIST) {
        ebpf_print("Malformed ORIGINATOR_ID\n");
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
        return 0;
    }
    return total_offset;
}