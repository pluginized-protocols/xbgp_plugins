//
// Created by thomas on 20/02/20.
//

#include <stdint.h>
#include "router_bgp_config.h"
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include <bytecode_public.h>

#include "../prove_stuffs/prove.h"

#ifdef PROVERS
uint8_t get_u8();
uint8_t *get_buf();

struct path_attribute *get_attr() {
    struct path_attribute *p_attr;
    p_attr = malloc(sizeof(*p_attr));
    if (!p_attr) return NULL;

    p_attr->code = get_u8();
    p_attr->flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;
    p_attr->length =  8;
    memcpy(p_attr->data, get_buf(), 8);

    return p_attr;
}

struct ubpf_peer_info *gpi(void);

struct ubpf_peer_info *get_src_peer_info() {
    struct ubpf_peer_info *pf = gpi();
    pf->peer_type = IBGP_SESSION;
}

#include "../prove_stuffs/mod_ubpf_api.c"
#endif


static __always_inline uint64_t encode_coord(int32_t coord[2]) {

    uint64_t _buf;
    uint8_t *buf = (uint8_t *) &_buf;

    *((uint32_t *) buf) = htonl(encode_number(coord[0]));
    *((uint32_t *) (buf+4)) = htonl(encode_number(coord[1]));

    return _buf;

}

static __always_inline int encode_attr(uint8_t code, const uint8_t *buf_in, uint8_t *buf_out) {

    int count = 0;
    int nb_peers;
    struct ubpf_peer_info *pinfo;

    switch (code) {
        case BA_GEO_TAG: {
            uint32_t lat, raw_lat;
            uint32_t lng, raw_lng;

            raw_lat = *((uint32_t *) (buf_in + count));
            lat = ebpf_ntohl(encode_number(raw_lat));
            *((uint32_t *) (buf_out + count)) = lat;
            count += 4;

            raw_lng = *((uint32_t *) (buf_in + count));
            lng = ebpf_htonl(encode_number(raw_lng));
            *((uint32_t *) (buf_out + count)) = lng;
            count += 4;
            break;
        }
        case PREFIX_ORIGINATOR:
            // this attribute must not encoded through an eBGP session
            // But it must be encoded for iBGP sessions
            pinfo = get_peer_info(&nb_peers);
            if (!pinfo) {
                ebpf_print("Unable to get peer info!\n");
                return -1;
            }

            if (pinfo->peer_type == EBGP_SESSION) return -1; // don't export the attribute
            *((uint64_t *)buf_out) = encode_coord((int32_t *)buf_in);
            return 8;

        default:
            return -1;
    }

    return count;
}

/**
 * Encode the current attribute decided by the protocol.
 * @param args unused -> use get_attr() API call to retrieve
 *                       the current attribute to encode.
 * @return Defined by the insertion point,
 *         0 when no bytes written
 *         else, the number of bytes written to the stream
 */
uint64_t generic_encode_attr(args_t *args __attribute__((unused))) {

    int ret_val = 0;
    uint32_t counter = 0;
    uint8_t *attr_buf;
    uint16_t tot_len = 0;

    struct path_attribute *attribute;
    attribute = get_attr();

    if (!attribute) return 0;

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

    ret_val = encode_attr(attribute->code, attribute->data, attr_buf + counter);
    if (ret_val == -1) return 0;

    counter += ret_val;

#ifdef PROVERS_SH
    BUF_GEN_ASSERT(attr_buf, attribute->code, 8, attribute->flags);
#endif

    if (write_to_buffer(attr_buf, counter) == -1) return 0;
    return counter;
}

#ifdef PROVERS
int main(void) {
    args_t args = {};
    uint64_t ret_val = generic_encode_attr(&args);

    return 0;
}
#endif