//
// Created by thomas on 20/05/20.
//

#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_rr.h"
#include "../prove_stuffs/prove.h"
#include "../prove_stuffs/prove_helpers.h"

/* starting point */
uint64_t encode_originator_id(args_t *args __attribute__((unused)));

PROOF_INSTS(
        uint16_t nondet_get_u32__verif(void);

        struct path_attribute *get_attr() {
            struct path_attribute *p_attr;
            p_attr = malloc(sizeof(*p_attr) + sizeof(uint32_t));
            if (!p_attr) return NULL;

            p_attr->code = ORIGINATOR_ID;
            p_attr->flags = ATTR_OPTIONAL;
            p_attr->length = 4;
            *(uint32_t *) p_attr->data = nondet_get_u32__verif();

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


uint64_t encode_originator_id(args_t *args __attribute__((unused))) {
    uint32_t counter = 0;
    int nb_peer;

    unsigned char originator_id[7];

    CREATE_BUFFER(originator_id, 7);

    struct path_attribute *originator_attr;

    struct ubpf_peer_info *to_info = NULL;
    struct ubpf_peer_info *src_info = NULL;

    to_info = get_peer_info(&nb_peer);

    if (!to_info) {
        ebpf_print("Can't get dst peer info\n");
        TIDYING()
        next();
        return 0;
    }

    if (to_info->peer_type != IBGP_SESSION) {
        ebpf_print("[ENCODE ORIGINATOR ID] Not an iBGP session\n");
        TIDYING()
        next();
    }

    src_info = get_src_peer_info();
    if (!src_info) {
        ebpf_print("[ENCODE ORIGINATOR ID] Unable to get src peer info\n");
        next();
    }

    originator_attr = get_attr_from_code(ORIGINATOR_ID_ATTR_ID);

    if (!originator_attr) {
        TIDYING();
        next();
        return 0;
    }

    originator_id[counter++] = originator_attr->flags;
    originator_id[counter++] = originator_attr->code;
    originator_id[counter++] = originator_attr->length;

    ebpf_memcpy(&originator_id[counter], originator_attr->data, originator_attr->length);
    counter += originator_attr->length;

    if (counter != 7) {
        ebpf_print("Size missmatch\n");
        TIDYING();
        next();
        return 0;
    }

    PROOF_SEAHORN_INSTS(
            p_assert(counter == 7);
            BUF_CHECK_ORIGINATOR(originator_id);
    )

    CHECK_BUFFER(originator_id, sizeof(originator_id));

    if (write_to_buffer(originator_id, sizeof(originator_id)) == -1) {
        ebpf_print("Write failed\n");
        next();
        return 0;
    }

    TIDYING()
    next();
    return counter;
}


PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret_val = encode_originator_id(&args);
            return ret_val;
        }
)
