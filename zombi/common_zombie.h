#ifndef XBGP_COMMON_ZOMBIE_H
#define XBGP_COMMON_ZOMBIE_H

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include <bytecode_public.h>
//#include "../../libxbgp/ubpf_api.h"

#define TYPE_REQUEST 8

typedef struct lp {
    struct ubpf_prefix* pfx;
    struct lp* next;
} list_prefix;

#endif //XBGP_COMMON_ZOMBIE_H