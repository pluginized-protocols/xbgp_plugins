//
// Created by thomas on 9/07/21.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"

void *memset(void *s, int c, size_t n);

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

uint64_t rib_test(UNUSED args_t *args) {
    int rib_fd;
    struct bgp_route *rte;
    char ip_str[60];
    rib_fd = new_rib_iterator(XBGP_AFI_IPV4,XBGP_SAFI_UNICAST);

    if (rib_fd < 0) {
        log_msg(L_INFO "Unable to get rib iterator");
        return -1;
    }

    while (rib_has_route(rib_fd)) {
        memset(ip_str, 0, sizeof(ip_str));
        rte = next_rib_route(rib_fd);

        // todo check if this omitting this lin is detected by CBMC
        if (rte == NULL) {
            log_msg(L_INFO "rte is null wtf ?");
            break;
        }

        if (ebpf_inet_ntop(rte->pfx.u, afi2af(rte->pfx.afi), ip_str, sizeof(ip_str)) != 0) {
            log_msg(L_INFO "Unable to convert IP prefix");
        } else {
            log_msg(L_INFO"Pfx %s/%d", LOG_PTR(ip_str), LOG_U16(rte->pfx.prefixlen));
        }

        del_bgp_route(rte);
        rte = NULL;
    }

    rib_iterator_clean(rib_fd);
    reschedule_plugin(NULL);
    return 0;
}