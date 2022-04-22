//
// Created by thomas on 10/02/22.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "propagation_time_common.h"
#include "../prove_stuffs/prove.h"

/* main entry point */
uint64_t encode_arrival_time_attr(args_t *args);

PROOF_INSTS(
#define PROVERS_ARG
#define NEXT_RETURN_VALUE EXIT_SUCCESS
        uint16_t nondet_u16(void);
        uint64_t nondet_u64(void);
        uint8_t nondet_u8(void);

        struct path_attribute *get_attr() {
            uint16_t len;
            struct path_attribute *p_attr = malloc(sizeof(struct path_attribute) + sizeof(struct attr_arrival));

            if (!p_attr) return NULL;

            p_attr->flags = ATTR_OPTIONAL|ATTR_TRANSITIVE;
            p_attr->code = nondet_u8();
            p_attr->length = sizeof(struct attr_arrival);

            struct attr_arrival *aa = (struct attr_arrival*)p_attr->data;
            aa->arrival_time.tv_sec = 0;
            aa->arrival_time.tv_nsec = 0;

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
        )

#define TIDYING() \
PROOF_INSTS(do {            \
    if (attribute) free(attribute); \
    if (dst_info) free(dst_info); \
} while(0))

uint64_t encode_arrival_time_attr(args_t *args UNUSED) {
    INIT_ARG_TYPE();
    SET_ARG_TYPE(ARRIVAL_TIME_ATTR);
    struct ubpf_peer_info *dst_info;
    struct timespec *in_time;
    struct path_attribute *attribute;
    struct attr_arrival *arrival;
    char attr_buf[ARRIVAL_TIME_ATTR_LEN + ATTR_HDR_LEN];
    char *attr = attr_buf;
    int nb_peer;

    //CREATE_BUFFER(attr_buf, ARRIVAL_TIME_ATTR_LEN + ATTR_HDR_LEN);

    attribute = get_attr();
    CHECK_ARG(attribute);

    dst_info = get_peer_info(&nb_peer);
    if (!dst_info) {
        TIDYING();
        next();
        CHECK_OUT();
        return 0;
    }

    if (!attribute) {
        TIDYING();
        next();
        CHECK_OUT();
        return 0;
    }

    if (attribute->code != ARRIVAL_TIME_ATTR) {
        TIDYING();
        next();
        CHECK_OUT();
        return 0;
    }

    arrival = (struct attr_arrival *) attribute->data;
    in_time = &arrival->arrival_time;

    if (dst_info->peer_type != IBGP_SESSION) {
        /*
         * this attribute is only written
         * to an iBGP peer
         */
        TIDYING();
        next();
        CHECK_OUT();
        return 0;
    }

    /* attr flags */
    write_u8(attr, ATTR_OPTIONAL);
    /* attr type */
    write_u8(attr, ARRIVAL_TIME_ATTR);
    /* attr length */
    write_u8(attr, ARRIVAL_TIME_ATTR_LEN);

    /* write the attribute */
    write_u64(attr, in_time->tv_sec);
    write_u64(attr, in_time->tv_nsec);
    write_u32(attr, arrival->from_as);

    /* make sure the offset pointer
     * has not overflowed nor underflow */
    //CHECK_BUFFER(attr_buf, sizeof(attr_buf));


    if (write_to_buffer((uint8_t *)attr_buf, sizeof(attr_buf)) != 0) {
        CHECK_OUT();
        TIDYING();
        return 0;
    }

    CHECK_OUT();
    TIDYING();
    return sizeof(attr_buf);
}

PROOF_INSTS(
        int main(void) {
            char attr_buf[ARRIVAL_TIME_ATTR_LEN + ATTR_HDR_LEN];
            args_t args = {};
            uint64_t ret_val = encode_arrival_time_attr(&args);

            p_assert(ret_val == 0 ||
            ret_val == sizeof(attr_buf));

            ctx_shmrm(42);

            return 0;
        }
        )