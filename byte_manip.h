//
// Created by thomas on 4/06/20.
//

#ifndef PLUGINIZED_BIRD_BYTE_MANIP_H
#define PLUGINIZED_BIRD_BYTE_MANIP_H

#define get_u32(data) \
({ \
    uint32_t a; \
    a = *((const uint32_t *) (data)); \
    ebpf_ntohl(a); \
})

#define get_u32_t2_friendly(data) ({                      \
    unsigned long __o__ = 0;                              \
    if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) {      \
        __o__ = ((((data) & 0x000000FFu) << 24u) |          \
                 (((data) & 0x0000FF00u) << 8u) |           \
                 (((data) & 0x00FF0000u) >> 8u) |           \
                 (((data) & 0xFF000000u) >> 24u));          \
    } else if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) {  \
        __o__ = data;                                     \
    }                                                     \
    __o__;                                                \
})

#endif //PLUGINIZED_BIRD_BYTE_MANIP_H
