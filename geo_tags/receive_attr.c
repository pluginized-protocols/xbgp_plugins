//
// Created by thomas on 19/02/20.
//

#include "public_bpf.h"
#include "ubpf_api.h"

static __always_inline unsigned int is_negative(uint32_t number) {
    return ((number & 0xffffffff) >> 31u) & 1u;
}

static __always_inline int32_t decode(uint32_t number) {
    if (!is_negative(number)) return number;
    return -(number & 0x7fffffffu);
}


static __always_inline int decode_attr(uint8_t code, uint16_t len, uint32_t flags, const uint8_t *data) {

    struct ubpf_peer_info *pinfo;

    switch (code) {
        case PREFIX_ORIGINATOR:
            pinfo = get_src_peer_info();
            if (!pinfo) {
                ebpf_print("Unable to get peer info !\n");
                return -1;
            }

            if (pinfo->peer_type == EBGP_SESSION) return -1;
            /* fallthrough */
        case BA_GEO_TAG: {
            if (len != 8) return -1; // malformed attribute

            uint32_t raw_latitude;
            uint32_t raw_longitude;

            int32_t geo_tag[2];
            uint64_t *attr_data;
            attr_data = (uint64_t *) geo_tag;

            raw_latitude = *((uint32_t *) data);
            data += 4;
            raw_longitude = *((uint32_t *) data);

            raw_latitude = ebpf_ntohl(raw_latitude);
            raw_longitude = ebpf_ntohl(raw_longitude);

            geo_tag[0] = decode(raw_latitude);
            geo_tag[1] = decode(raw_longitude);

            return add_attr(code, flags, len, (uint8_t *) attr_data) == -1 ? -1 : 0;
        }
        default:
            return -1;
    }
    return 0;
}

/**
 * Decode a given attribute passed by the protocol
 * @param args contains the current attribute
 * @return EXIT_SUCCESS if the attribute has been decoded and stored in the protocol memory
 *         EXIT_FAILURE otherwise. The protocol itself must decode this attribute.
 */
uint64_t generic_decode_attr(bpf_full_args_t *args) {

    uint8_t *code;
    uint16_t *len;
    uint8_t *flags;
    uint8_t *data;

    code = bpf_get_args(0, args);
    flags = bpf_get_args(1, args);
    data = bpf_get_args(2, args);
    len = bpf_get_args(3, args);

    if (!code || !len || !flags || !data) {
        return EXIT_FAILURE;
    }

    return decode_attr(*code, *len, *flags, data) == -1 ? EXIT_FAILURE : EXIT_SUCCESS;
}