//
// Created by thomas on 20/02/20.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include <stdint.h>

#include "router_bgp_config.h"

#include "../prove_stuffs/prove.h"

/* starting point */
uint64_t write_attr(void);

PROOF_INSTS(
#define NEXT_RETURN_VALUE FAIL
        uint8_t nondet_u8(void);
        uint64_t nondet_u64(void);

        struct path_attribute *get_attr() {
            struct path_attribute *p_attr;
            p_attr = malloc(sizeof(*p_attr) + 8);
            if (!p_attr) return NULL;

            p_attr->code = nondet_u8();
            p_attr->flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;
            p_attr->length = 8;
            *(uint64_t *) p_attr->data = nondet_u64();

            return p_attr;
        }

        struct ubpf_peer_info *get_src_peer_info() {
            struct ubpf_peer_info *pf;

            pf = malloc(sizeof(*pf));

            if (!pf) return NULL;
            pf->peer_type = nondet_u8();
            return pf;
        }

        struct ubpf_peer_info *get_peer_info() {
            return get_src_peer_info();
        }

)

static __always_inline int encode_attr(uint8_t code, const uint8_t *buf_in, uint8_t *buf_out) {

    int count = 0;
    int nb_peers;
    struct ubpf_peer_info *pinfo;

    switch (code) {
        case BA_GEO_TAG: {
            uint32_t lat, raw_lat;
            uint32_t lng, raw_lng;

            raw_lat = *((const uint32_t *) (buf_in + count));
            lat = ebpf_ntohl(raw_lat);
            *((uint32_t *) (buf_out + count)) = lat;
            count += 4;

            raw_lng = *((const uint32_t *) (buf_in + count));
            lng = ebpf_htonl(raw_lng);
            *((uint32_t *) (buf_out + count)) = lng;
            count += 4;
            break;
        }
        case PREFIX_ORIGINATOR:
            // this attribute must not encoded through an eBGP session
            // But it must be encoded for iBGP sessions
            pinfo = get_peer_info(&nb_peers);
            geo_tags_t *geo;

            if (!pinfo) {
                ebpf_print("Unable to get peer info!\n");
                PROOF_INSTS(if (pinfo) free(pinfo););
                return -1;
            }
            geo = (geo_tags_t *) buf_in;

            if (pinfo->peer_type == EBGP_SESSION) {
                PROOF_INSTS(if (pinfo) free(pinfo););
                return -1; // don't export the attribute
            }
            *((uint64_t *) buf_out) = coord_hton(geo);
            PROOF_INSTS(if (pinfo) free(pinfo););
            return 8;
        case MULTI_EXIT_DISC_ATTR_ID:
            // we must handle MED ourselves because it is
            // not handled by the host implementation now !
            *(uint32_t *) buf_out = ebpf_htonl(*(uint32_t *)buf_in);
            return 4;

        default:
            return -1;
    }

    return count;
}

#define TIDYING() \
PROOF_INSTS(do {            \
    if (attribute) free(attribute); \
    if (attr_buf) free(attr_buf); \
} while(0))


/**
 * Encode the current attribute decided by the protocol.
 * @param args unused -> use get_attr() API call to retrieve
 *                       the current attribute to encode.
 * @return Defined by the insertion point,
 *         0 when no bytes written
 *         else, the number of bytes written to the stream
 */
uint64_t write_attr(void) {
    int ret_val;
    uint32_t counter = 0;
    uint8_t *attr_buf = NULL;
    uint16_t tot_len = 0;

    struct path_attribute *attribute;
    attribute = get_attr();

    if (!attribute) {
        TIDYING();
        next();
        return 0;
    }

    tot_len += 2; // Type hdr
    tot_len += attribute->length < 256 ? 1 : 2; // Length hdr
    tot_len += attribute->length;

    attr_buf = ctx_calloc(1, tot_len);
    if (!attr_buf) {
        TIDYING();
        next();
        return 0;
    }

    attr_buf[counter++] = attribute->flags;
    attr_buf[counter++] = attribute->code;

    if (attribute->length < 256) attr_buf[counter++] = (uint8_t) attribute->length;
    else {
        attr_buf[counter] = attribute->length;
        counter += 2;
    }

    ret_val = encode_attr(attribute->code, attribute->data, attr_buf + counter);
    if (ret_val == -1) {
        TIDYING();
        // should call the following function here.
        // Maybe other plugins handle the attribute
        // or the host implementation.
        next();
        return 0;
    }

    counter += ret_val;

    PROOF_SEAHORN_INSTS(
            BUF_GEN_ASSERT(attr_buf, attribute->code, 8, attribute->flags);
    )



    if (write_to_buffer(attr_buf, counter) == -1) {
        TIDYING();
        next();
        return 0;
    }
    TIDYING();
    return counter;
}

PROOF_INSTS(
        int main(void) {
            uint64_t ret_val = write_attr();

            return 0;
        }
)