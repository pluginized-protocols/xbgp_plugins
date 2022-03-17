//
// Created by thomas on 17/03/21.
//
#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../prove_stuffs/prove.h"


/* starting point */
uint64_t route_origin_monitor(args_t *args UNUSED);

PROOF_SEAHORN_INSTS (

#define ORIGIN_ATTR 1

#define ORIGIN_ATTR_IGP 0
#define ORIGIN_ATTR_EGP 1
#define ORIGIN_ATTR_UNK 2

char int2char(int c)
{
    switch (c) {
        case 0:
            return '0';
        case 1:
            return '1';
        case 2:
            return '2';
        case 3:
            return '3';
        case 4:
            return '4';
        case 5:
            return '5';
        case 6:
            return '6';
        case 7:
            return '7';
        case 8:
            return '8';
        default:
            return '9';
    }
}
void *char2string(u_char c, char *dst)
{
    int i = 0;
    int d1 = c / 100;
    int r1 = c % 100;
    if (d1)
        dst[i++] = int2char(d1);
    int d2 = r1 / 10;
    int r2 = r1 % 10;
    if (d2)
        dst[i++] = int2char(d2);
    dst[i++] = int2char(r2);

    return dst+i;
}

void *memset(void *s, int c, size_t n);

)

PROOF_INSTS(
        uint8_t nondet_u8(void);

        struct path_attribute *get_attr_from_code(uint8_t code) {
            struct path_attribute *pattr;
            if (code != ORIGIN_ATTR) {
                return NULL;
            }

            pattr = malloc(sizeof(*pattr) + 1);
            if (!pattr) return NULL;

            pattr->data[0] = nondet_u8();
            return pattr;
        }

        struct ubpf_prefix *get_prefix(void){
            return malloc(sizeof(struct ubpf_prefix));
        }
)

#define TIDYING() \
PROOF_INSTS(do { \
    if (p) free(p); \
    if (attr) free(attr); \
} while(0);)

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

    if (!attr || !p) {
        TIDYING();
        return EXIT_FAILURE;
    }

    memset(prefix_addr, 0, sizeof(prefix_addr));

    if (ebpf_inet_ntop(p->u, p->afi, prefix_addr, sizeof(prefix_addr)) != 0) {
        log_msg("Unable to convert IP address from binary to text\n");
        TIDYING();
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

    CHECK_STRING(prefix_addr, 52);

    log_msg(L_INFO "Received route %s/%d. Origin %s",
            LOG_PTR(prefix_addr), LOG_U16(p->prefixlen), LOG_PTR((void *)origin_txt));

    TIDYING();
    return EXIT_SUCCESS;
}


PROOF_INSTS(
        int main(void) {
            uint64_t ret;
            args_t args = {};
            ret = route_origin_monitor(&args);
            p_assert(ret == EXIT_FAILURE || ret == EXIT_SUCCESS);
            return 0;
        }
)