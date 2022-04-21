//
// Created by thomas on 11/02/22.
//

#ifndef XBGP_PLUGINS_PROPAGATION_TIME_COMMON_H
#define XBGP_PLUGINS_PROPAGATION_TIME_COMMON_H

#include "../prove_stuffs/prove.h"

#define ARRIVAL_TIME_ATTR 45

#define ATTR_HDR_LEN 3
#define ARRIVAL_TIME_ATTR_LEN 20

#define COMMUNITY_ARRIVAL_TAG 65000

// NETWORK BYTEORDER COMMUNITY_ARRIVAL_TAG (65000)
#define COMMUNITY_ARRIVAL_TAG_BE 59645

#ifdef DEBUG
#define c_assert(cond) \
do {                 \
    if (!(cond)) {     \
        ebpf_print("Assertion \"%s\" failed\n", LOG_PTR(#cond));               \
    }\
} while(0)
#else
#define c_assert(cond)
#endif

struct attr_arrival {
    struct timespec arrival_time;
    uint32_t from_as;
};

#define NS_TO_MS ((unsigned int)1000000)

#define timespec2ms(a) ({             \
    uint16_t resms__ = 0;             \
    uint64_t ms__ = 0;                \
    ms__ = (a)->tv_sec;               \
    ms__ += (uint64_t) (a)->tv_nsec / NS_TO_MS;  \
                                      \
    if (ms__ <= UINT16_MAX) {         \
        resms__ = ms__;               \
    }                                 \
    resms__;                          \
})



#define timespec_diff(a, b, result)                  \
  do {                                                \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;     \
    (result)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec;  \
    if ((result)->tv_nsec < 0) {                      \
      --(result)->tv_sec;                             \
      (result)->tv_nsec += 1000000000;                \
    }                                                 \
  } while (0)

#define write_uxx(buf, val, size, type, fun) \
do {                        \
    *((type *) (buf)) = fun(val); \
    (buf) += (size);\
} while(0)


#define write_u8(buf, val) write_uxx(buf, val, 1, uint8_t, )

#define write_u16(buf, val) write_uxx(buf, val, 2, uint16_t, ebpf_htons)

#define write_u32(buf, val) write_uxx(buf, val, 4, uint32_t, ebpf_htonl)

#define write_u64(buf, val) write_uxx(buf, val, 8, uint64_t, ebpf_htonll)

#define read_uxx(buf, size, type, fun) \
({                                     \
    type __rdval__;                    \
    __rdval__ = fun(*((type *) (buf)));\
    (buf) += (size);                     \
    __rdval__;\
})

#define read_u8(buf) read_uxx(buf, 1, uint8_t, )

#define read_u16(buf) read_uxx(buf, 2, uint16_t, ebpf_ntohs)

#define read_u32(buf) read_uxx(buf, 4, uint32_t, ebpf_ntohl)

#define read_u64(buf) read_uxx(buf, 8, uint64_t, ebpf_ntohll)


static __always_inline int write_attr(uint8_t code, uint8_t flags, uint16_t length, uint8_t *data) {
    uint8_t *attr_buf;
    uint8_t *attr_offset;
    int big_length;
    size_t tot_length;
    int res;

    size_t hdr_length = ATTR_HDR_LEN;
    if ((big_length = length > UINT8_MAX)) hdr_length += 1;

    tot_length = length + hdr_length;

    attr_buf = ctx_malloc(tot_length);

    CREATE_BUFFER(attr_buf, tot_length);

    if (!attr_buf) return -1;
    attr_offset = attr_buf;

    write_u8(attr_offset, flags);
    write_u8(attr_offset, code);

    if (big_length) {
        write_u16(attr_offset, length);
    } else {
        write_u8(attr_offset, (uint8_t) length);
    }

    ebpf_memcpy(attr_offset, data, length);
    attr_offset += length;

    if (attr_offset != attr_buf + tot_length) {
        ebpf_print("[BUG!] INVALID ATTR FORMAT\n");
        return 0;
    }

    CHECK_BUFFER(attr_buf, tot_length);

    res = write_to_buffer(attr_buf, tot_length);

    ctx_free(attr_buf);
    return res == 0 ? tot_length : 0;
}


#endif //XBGP_PLUGINS_PROPAGATION_TIME_COMMON_H
