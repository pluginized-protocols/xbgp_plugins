//
// Created by thomas on 20/05/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_rr.h"
#include "../prove_stuffs/prove.h"

/* starting point */
uint64_t encode_originator_id(args_t *args __attribute__((unused)));

PROOF_INSTS(
        uint16_t nondet_get_u32__verif();

        struct path_attribute *get_attr() {
            struct path_attribute *p_attr;
            p_attr = malloc(sizeof(*p_attr));
            if (!p_attr) return NULL;

            p_attr->code = ORIGINATOR_ID;
            p_attr->flags = ATTR_OPTIONAL;
            p_attr->length = 4;
            *(uint32_t *) p_attr->data = nondet_get_u32__verif();

            return p_attr;
        }

        struct ubpf_peer_info *gpi(void);

        struct ubpf_peer_info *get_src_peer_info() {
            struct ubpf_peer_info *pf = gpi();
            pf->peer_type = IBGP_SESSION;
        }
)


uint64_t encode_originator_id(args_t *args __attribute__((unused))) {

    uint32_t counter = 0;
    uint8_t *attr_buf;
    uint16_t tot_len = 0;
    uint32_t *originator_id;
    int nb_peer;

    struct path_attribute *attribute;
    attribute = get_attr();

    if (!attribute) {
        ebpf_print("Unable to get attribute\n");
        return 0;
    }

    struct ubpf_peer_info *to_info;
    to_info = get_peer_info(&nb_peer);

    if (!to_info) {
        ebpf_print("Can't get src and peer info\n");
        return 0;
    }

    if (to_info->peer_type != IBGP_SESSION) {
        ebpf_print("[ENCODE ORIGINATOR ID] Not an iBGP session\n");
        next();
    }


    if (attribute->code != ORIGINATOR_ID) next();

    tot_len += 2; // Type hdr
    tot_len += attribute->length < 256 ? 1 : 2; // Length hdrs
    tot_len += attribute->length;

    attr_buf = ctx_calloc(1, tot_len);
    if (!attr_buf) {
        ebpf_print("Memory alloc failed\n");
        return 0;
    }

    attr_buf[counter++] = attribute->flags;
    attr_buf[counter++] = attribute->code;

    if (attribute->length < 256) attr_buf[counter++] = (uint8_t) attribute->length;
    else {
        attr_buf[counter] = attribute->length;
        counter += 2;
    }

    originator_id = (uint32_t *) attribute->data;
    uint32_t originator_id_net = ebpf_htonl(*originator_id);
    // ebpf_print("Originator id %u (htonl %u)\n", *originator_id, ebpf_htonl(*originator_id));
    // *((uint32_t *)(attr_buf + counter)) = ebpf_htonl(*originator_id);
    memcpy(attr_buf + counter, &originator_id_net, sizeof(originator_id_net));

    counter += 4;

    if (counter != tot_len) {
        ebpf_print("Size missmatch\n");
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