//
// Created by thomas on 9/07/21.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"

void *memset(void *s, int c, size_t n);

void *memcpy(void *restrict dest, const void *restrict src, size_t n);

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

static __always_inline void del_bgp_route(struct bgp_route *rte) {
    int i;
    if (!rte) return;

    if (rte->peer_info->local_bgp_session != NULL) {
        log_msg(L_INFO"WTF local session ??");
        ctx_free(rte->peer_info->local_bgp_session);
    }
    if (rte->peer_info) ctx_free(rte->peer_info);

    if (rte->attr) {
        for (i = 0; i < rte->attr_nb; i++) {
            if (rte->attr[i]) ctx_free(rte->attr[i]);
        }
        ctx_free(rte->attr);
    }
    ctx_free(rte);
}

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

    origin = *attr->data;

    if (origin > sizeof(origins) / sizeof(origins[0])) {
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

uint64_t rib_test(UNUSED args_t *args) {
    int rib_fd;
    struct bgp_route *rte;
    char ip_str[60];
    char next_hop[60];
    char *as_path; // alloc in the heap to save stack memory
    const char unk[] = "???";
    rib_fd = new_rib_iterator(XBGP_AFI_IPV4, XBGP_SAFI_UNICAST);

    if (rib_fd < 0) {
        return -1;
    }

    as_path = ctx_malloc(512);
    if (!as_path) return -1;

    while (rib_has_route(rib_fd)) {
        memset(ip_str, 0, sizeof(ip_str));
        rte = next_rib_route(rib_fd);

        // todo check if this omitting this lin is detected by CBMC
        if (rte == NULL) {
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
                memcpy(next_hop, unk, sizeof (unk));
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

    rib_iterator_clean(rib_fd);
    reschedule_plugin(NULL);
    return 0;
}
