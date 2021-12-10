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
)



/* starting point */
uint64_t test_rib(UNUSED args_t *args);

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
    for (i = 0; i < nb_attrs; i++) {
        if (attrs[i]->code == code) {
            return attrs[i];
        }
    }
    return NULL;
}


static __always_inline size_t as_path2_str(struct path_attribute *attr, char *buf, size_t len) {
    int i, j;
    size_t offset = 0;
    uint8_t *as_path;
    uint32_t *as_segment;
    uint8_t seg_type;
    uint8_t seg_len;
    int chars_written;
    uint32_t cur_as;
    const char end_bracket[] = " ]";

    if (attr == NULL) {
        return 0;
    } else if (attr->code != AS_PATH_ATTR_ID) {
        return 0;
    }

    as_path = attr->data;
    buf[offset++] = '[';

    for (i = 0; i < attr->length;) {
        if (attr->length - i < 2) return 0;
        seg_type = as_path[i++];
        seg_len = as_path[i++];

        switch (seg_type) {
            case AS_PATH_SEGMENT_SET:
            case AS_PATH_SEGMENT_SEQUENCE:
            case AS_PATH_SEGMENT_CONFED_SEQUENCE:
            case AS_PATH_SEGMENT_CONFED_SET:
                break;
            default:
                return 0;
        }

        as_segment = (uint32_t *) &as_path[i];
        if (attr->length - i < seg_len * 4) return 0;
        for (j = 0; j < seg_len; j++) {
            cur_as = ebpf_ntohl(as_segment[j]);
            chars_written = ubpf_sprintf(&buf[offset], len - offset, " %d", cur_as);
            offset += chars_written;
            if (offset >= len) return len;
        }
        i += seg_len * 4;
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

uint64_t test_rib(UNUSED args_t *args) {
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

    while (rib_has_route(rib_fd)) {

        rte = next_rib_route(rib_fd);

        if (rte == NULL) {
            break;
        }

        memset(ip_str, 0, sizeof(ip_str));

        if (rte->pfx.afi != AF_INET && rte->pfx.afi != AF_INET6) {
            del_bgp_route(rte);
            break;
        }

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

            ret = test_rib(&args);

            return 0;
        }
)