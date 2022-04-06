//
// Created by thomas on 9/07/21.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"

#include "../prove_stuffs/prove.h"

static __always_inline void del_bgp_route(struct bgp_route *rte) {
    int i;
    if (!rte) return;

    if (rte->peer_info) {
        if (rte->peer_info->local_bgp_session != NULL) {
            log_msg(L_INFO"WTF local session ??");
            ctx_free(rte->peer_info->local_bgp_session);
        }

        ctx_free(rte->peer_info);
    }


    if (rte->attr) {
        for (i = 0; i < rte->attr_nb; i++) {
            if (rte->attr[i]) ctx_free(rte->attr[i]);
        }
        ctx_free(rte->attr);
    }
    ctx_free(rte);
}

PROOF_INSTS(
        int nondet_int(void);
        uint16_t nondet_u16(void);
        uint8_t nondet_u8(void);

        struct ubpf_prefix nondet_pfx(void);

        struct bgp_route *next_rib_route(unsigned int iterator_id) {
            struct bgp_route *rte;
            int nb_attr;

            nb_attr = nondet_int() % 20;
            if (nb_attr <= 0) return NULL;
            if (nb_attr > 20) return NULL;

            rte = calloc(1, sizeof(struct bgp_route));
            if (!rte) { return NULL; }

            rte->attr = calloc(nb_attr, sizeof(struct path_attribute *));

            if (!rte->attr) {
                free(rte);
                return NULL;
            }

            rte->pfx = nondet_pfx();
            for (int op = 0; op < sizeof(rte->pfx.u); op++) {
                rte->pfx.u[op] = nondet_u8();
            }

            rte->attr_nb = nb_attr;

            /* reserve space for attributes */
            for (int i = 0; i < nb_attr; i++) {
                uint16_t attr_len = nondet_u16();
                if (attr_len > 4096) {
                    del_bgp_route(rte);
                    return NULL;
                }
                rte->attr[i] = malloc(sizeof(struct path_attribute) + attr_len);
                if (!rte->attr[i]) {
                    del_bgp_route(rte);
                    return NULL;
                }
                rte->attr[i]->length = attr_len;
            }

            return rte;
        }

        int rib_has_route(unsigned int iterator_id) {
            return nondet_int() % 2 == 0;
        }

        void rib_iterator_clean(unsigned int iterator_id) {

        }

        int reschedule_plugin(time_t *time) {
            return 0;
        }

        int new_rib_iterator(int afi, int safi) {
            return 1;
        }
)



/* starting point */
uint64_t rib_walk(UNUSED args_t *args);

#define afi2af(afi) ({          \
  int af__;                     \
  switch ((afi)) {              \
    case XBGP_AFI_IPV4:         \
      af__ = AF_INET;           \
      break;                    \
    case XBGP_AFI_IPV6:         \
      af__ = AF_INET6;          \
      break;                    \
    default:                    \
      af__ = -1;                \
  }                             \
  af__;                         \
})

static __always_inline struct path_attribute *find_by_code(struct path_attribute **attrs, uint8_t code, int nb_attrs) {
    int i;
    for (i = 0; i < nb_attrs && i < 50; i++) {
        if (attrs[i]->code == code) {
            return attrs[i];
        }
    }
    return NULL;
}


static __always_inline unsigned int conv_asn(void *as_segment_, unsigned nb_as,
                                    char *buf, unsigned long len) {
    unsigned int j;
    unsigned int chars_written;
    unsigned int offset;
    uint32_t cur_as;
    uint32_t *as_segment =  as_segment_;

    chars_written = 0;
    offset = 0;

    for (j = 0; j < nb_as && j < 256; j++) {
#ifndef PROVERS_T2
        cur_as = ebpf_ntohl(as_segment[j]);
        chars_written = ubpf_sprintf(&buf[offset], len - offset, " %d", cur_as);
#else
        cur_as = as_segment[j];
        chars_written = rnd_int();
        if (chars_written <= 0) return 0;
#endif
        offset += chars_written;
        if (offset >= len) return 0;
    }
    return offset;
}


static __always_inline size_t as_path2_str(struct path_attribute *attr, char *buf, unsigned long len) {
    unsigned int offset = 0;
    uint8_t *as_path;
    uint32_t *as_segment;
    unsigned char seg_type;
    unsigned char seg_len;
    const char end_bracket[] = " ]";

    PROOF_T2_INSTS(unsigned int trap = 0;)

    if (attr == NULL) {
        return 0;
    }
    if (attr->code != AS_PATH_ATTR_ID) {
        return 0;
    }

    as_path = attr->data;
    buf[offset++] = '[';

    unsigned int bytes = 0;
    unsigned int tot_len = attr->length;

    while (bytes < tot_len PROOF_T2_INSTS(&& trap < 4096)) {
        PROOF_T2_INSTS(trap += 6;)
        if (tot_len - bytes <= 2) return 0;
        seg_type = as_path[bytes++];
        seg_len = as_path[bytes++];

        if (seg_len <= 0)
            continue;

        if (bytes + (4*seg_len) > tot_len)
            break; // / * woah malformed update * /
        bytes += seg_len * 4;

        switch (seg_type) {
            case AS_PATH_SEGMENT_SET:
            case AS_PATH_SEGMENT_SEQUENCE:
            case AS_PATH_SEGMENT_CONFED_SEQUENCE:
            case AS_PATH_SEGMENT_CONFED_SET:
                break;
            default:
                return 0;
        }

        as_segment = (uint32_t *) &as_path[bytes];

        if (seg_len <= 0) return 0;

        unsigned int tmp_offset;

        tmp_offset = conv_asn(as_segment, seg_len, buf + offset, len - offset);
        if (tmp_offset == 0) return len;
        offset += tmp_offset;
        if (offset >= len) return len;
    }

    if (len - sizeof(end_bracket) >= offset) {
        memcpy(&buf[offset], end_bracket, sizeof(end_bracket));
        offset += sizeof(end_bracket);
    }

    return offset;
}

static __always_inline const char *origin2str(struct path_attribute *attr) {
    uint8_t origin;
    const char *igp = "IGP";
    const char *egp = "EGP";
    const char *unk = "incomplete";

    const char *origins[] = {
            [BGP_ORIGIN_INCOMPLETE] = igp,
            [BGP_ORIGIN_EGP] = egp,
            [BGP_ORIGIN_IGP] = unk,
    };

    if (!attr) {
        log_msg(L_INFO"Origin not found");
        return NULL;
    }
    if (attr->code != ORIGIN_ATTR_ID) {
        log_msg(L_INFO"Attr code Origin mismatch");
        return NULL;
    }

    if (attr->length != 1) return NULL;

    origin = *attr->data;

    if (origin >= sizeof(origins) / sizeof(origins[0])) {
        log_msg(L_INFO"Origin not recognized ? %d", LOG_U8(origin));
        return NULL;
    }

    return origins[origin];
}

static __always_inline int nexthop2str(struct path_attribute *attr, char *buf, size_t len) {
    if (!attr) return -1;
    if (attr->code != NEXT_HOP_ATTR_ID) return -1;

    return ebpf_inet_ntop(attr->data, AF_INET, buf, len);
}

uint64_t rib_walk(UNUSED args_t *args) {
    unsigned long int iter;
#define MAXITER 18446744073709551615u  // assume MAX routes in routing table = 2^64 (~18 446 Peta routes) (actually 1M for IPv4 (2021))
    int rib_fd;
    struct bgp_route *rte;
    char ip_str[60];
    char next_hop[60];
    char *as_path; // alloc in the heap to save stack memory
    const char unk[] = "???";
    rib_fd = new_rib_iterator(XBGP_AFI_IPV4, XBGP_SAFI_UNICAST);

    if (rib_fd < 0) {
        return FAIL;
    }

    as_path = ctx_malloc(512);
    if (!as_path) return -1;

    iter = 0;
    while (rib_has_route(rib_fd) && iter < MAXITER) {
        iter += 1;

        rte = next_rib_route(rib_fd);

        if (rte == NULL) {
            break;
        }

        memset(ip_str, 0, sizeof(ip_str));

        if (ebpf_inet_ntop(rte->pfx.u, afi2af(rte->pfx.afi), ip_str, sizeof(ip_str)) != 0) {
            log_msg(L_INFO "Unable to convert IP prefix");
        } else {
            // parse as_path
            memset(as_path, 0, 512);
            memset(next_hop, 0, sizeof(next_hop));

            if (as_path2_str(find_by_code(rte->attr, AS_PATH_ATTR_ID, rte->attr_nb),
                             as_path, 512) == 0) {
                log_msg(L_INFO "Failed to convert aspath ?");
            }

            // nexthop
            if (nexthop2str(find_by_code(rte->attr, NEXT_HOP_ATTR_ID, rte->attr_nb), next_hop, sizeof(next_hop)) != 0) {
                memcpy(next_hop, unk, sizeof(unk));
            }

            CHECK_STRING(ip_str, 60);
            CHECK_STRING(as_path, 512);
            CHECK_STRING(origin2str(find_by_code(rte->attr, ORIGIN_ATTR_ID, rte->attr_nb)), 11);
            CHECK_STRING(next_hop, 60);

            log_msg(L_INFO"Pfx %s/%d %s %s via %s",
                    LOG_STR(ip_str),
                    LOG_U16(rte->pfx.prefixlen),
                    LOG_STR(as_path),
                    LOG_STR(origin2str(find_by_code(rte->attr, ORIGIN_ATTR_ID, rte->attr_nb))),
                    LOG_STR(next_hop)
            );
        }

        del_bgp_route(rte);
        rte = NULL;
    }

    ctx_free(as_path);

    rib_iterator_clean(rib_fd);
    reschedule_plugin(NULL);
    return 0;
}


PROOF_INSTS(
        int main(void) {
            uint64_t ret;
            args_t args = {};

            ret = rib_walk(&args);
            p_assert(ret == EXIT_SUCCESS || ret == EXIT_FAILURE);

            return 0;
        }
)