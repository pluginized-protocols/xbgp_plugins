//
// Created by thomas on 17/03/21.
//
#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"


/* starting point */
uint64_t route_origin_monitor(args_t *args UNUSED);

#define ORIGIN_ATTR 1

#define ORIGIN_ATTR_IGP 0
#define ORIGIN_ATTR_EGP 1
#define ORIGIN_ATTR_UNK 2


const char *igp = "IGP";
const char *egp = "EGP";
const char *unk = "INCOMPLETE";

uint64_t route_origin_monitor(args_t *args UNUSED) {
    struct path_attribute *attr;
    struct ubpf_prefix *p;
    char prefix_addr[52];
    const char *origin_txt;
    uint8_t origin;

    attr = get_attr_from_code(ORIGIN_ATTR);
    p = get_prefix();

    if (!attr || !p) return EXIT_FAILURE;

    memset(prefix_addr, 0, sizeof(prefix_addr));

    if (ebpf_inet_ntop(p->u, p->afi, prefix_addr, sizeof(prefix_addr)) != 0) {
        log_msg("Unable to convert IP address from binary to text\n");
        return EXIT_FAILURE;
    }

    origin = *attr->data;

    switch (origin) {
        case ORIGIN_ATTR_IGP:
            origin_txt = igp;
            break;
        case ORIGIN_ATTR_EGP:
            origin_txt = egp;
            break;
        default:
            origin_txt = unk;
    }

    log_msg(L_INFO "Received route %s/%d. Origin %s",
            LOG_PTR(prefix_addr), LOG_U16(p->prefixlen), LOG_PTR(origin_txt));

    return EXIT_SUCCESS;
}