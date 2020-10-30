//
// Created by thomas on 20/05/20.
//

#include "../../public_bpf.h"
#include "ubpf_api.h"
#include "common_rr.h"

uint64_t encode_originator_id(bpf_full_args_t *args __attribute__((unused))) {

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
    tot_len += attribute->len < 256 ? 1 : 2; // Length hdrs
    tot_len += attribute->len;

    attr_buf = ctx_calloc(1, tot_len);
    if (!attr_buf) {
        ebpf_print("Memory alloc failed\n");
        return 0;
    }

    attr_buf[counter++] = attribute->flags;
    attr_buf[counter++] = attribute->code;

    if (attribute->len < 256) attr_buf[counter++] = (uint8_t) attribute->len;
    else {
        attr_buf[counter] = attribute->len;
        counter += 2;
    }

    originator_id = (uint32_t *) attribute->data;
    *((uint32_t *)(attr_buf + counter)) = ebpf_htonl(*originator_id);

    counter += 4;

    if(counter != tot_len) {
        ebpf_print("Size missmatch\n");
        return 0;
    }

    if (write_to_buffer(attr_buf, counter) == -1) {
        ebpf_print("Write failed\n");
        return 0;
    }

    return counter;
}