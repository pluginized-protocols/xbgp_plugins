#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../prove_stuffs/prove.h"

#include "common_zombie.h"

#define AS_PATH	    0x02
#define NEXT_HOP    0x03
struct ubpf_peer_info* peer;
uint8_t* buf;

uint64_t decode_msg(args_t *args UNUSED);

PROOF_INSTS(
#define NEXT_RETURN_VALUE EXIT_SUCCESS

        uint8_t nondet_u8(void);
        int nondet_int(void);
        unsigned int nondet_uint(void);

        static uint16_t data_length = 0;

        void *get_arg(unsigned int id) {

            switch (id) {
                case ARG_LENGTH: {
                    if (data_length == 0) {
                        data_length = 19+26*nondet_u8();
                    }
                    uint16_t* length = malloc(sizeof(*length));
                    *length = data_length;
                    return length;
                }
                case ARG_BGP_MESSAGE: {
                    if (data_length == 0) {
                        data_length = 19+26*nondet_u8();
                    }
                    uint8_t* buf = malloc(data_length);
                    if (!buf) return NULL;
                    uint8_t* data = buf;

                    data += 16; // skip the marker
                    uint16_t* tmp = (uint16_t*) data;
                    *tmp = data_length;
                    data += sizeof(uint16_t);
                    *data = nondet_u8();
                    data++;
                    for (int i = 0 ; i < data_length-19 ; i++)
                        data[i] = nondet_u8();

                    return buf;
                }
                default:
                    return NULL;
            }
        }

        struct ubpf_peer_info *get_src_peer_info() {
            struct ubpf_peer_info *pf;

            pf = malloc(sizeof(*pf));
            if (!pf) return NULL;

            return pf;
        }

        struct bgp_route *get_rib_out_entry(uint8_t af_family, struct ubpf_prefix *pfx, struct ubpf_peer_info *pinfo) {
            struct bgp_route *ret = malloc(sizeof(struct bgp_route));
            ret->attr_nb = nondet_int();
            p_assume(ret->attr_nb >= 0);
            ret->attr = malloc(sizeof(struct path_attribute*) * ret->attr_nb);
            for (int i = 0 ; i < ret->attr_nb ; i++) {
                unsigned int tmp_len = nondet_uint();
                ret->attr[i] = malloc(sizeof(struct path_attribute) + tmp_len);
                ret->attr[i]->length = tmp_len;
                ret->attr[i]->code = nondet_u8();
                ret->attr[i]->flags = nondet_u8();
            }
            return ret;
        }
)

#ifndef PROVERS_T2
#include "send_update.c"
#else
uint64_t __always_inline send_update(struct host* host_cur, struct pf** pf_cur, struct bgp_route* ure);
#endif

#define TIDYING() \
PROOF_INSTS(do {            \
if(ghost_data) free(ghost_data); \
if(len) free(len);\
if(buf) free(buf);\
if(peer) free(peer);\
destruct();       \
} while(0))

uint64_t decode_msg(args_t *args UNUSED) {
    uint16_t *len;
    uint8_t *data;
    data = get_arg(ARG_BGP_MESSAGE);
    len = get_arg(ARG_LENGTH); // longueur totale du buffer data
    init();
    peer = get_src_peer_info();
    buf = ctx_malloc(4096-19);
    PROOF_INSTS(uint8_t *ghost_data = data;)
    if (!len || !data || !buf || !peer) {
        TIDYING();
        return EXIT_FAILURE;
    }
#ifdef PROVERS
    if (!(data+*len))
        return EXIT_FAILURE;
#endif
    data += 16; // skip the marker
    data += sizeof(uint16_t);
    uint8_t type = *data;
    data += sizeof(uint8_t);
    // continue parsing
    if (type != TYPE_REQUEST) {
        TIDYING();
        next();
    }

    TIDYING();
    return 0;
}

PROOF_INSTS(
    int main(void) {
        args_t args = {};
        uint64_t ret;
        ret = decode_msg(&args);
        return 0;
    }
    )
