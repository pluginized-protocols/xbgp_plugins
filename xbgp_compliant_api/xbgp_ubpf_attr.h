//
// Created by thomas on 23/11/20.
//

#ifndef PLUGINIZED_FRR_XBGP_UBPF_ATTR_H
#define PLUGINIZED_FRR_XBGP_UBPF_ATTR_H

#include <stddef.h>
#include <string.h>
#include "xbgp_defs.h"

#define ATTR_FLAG_OPT_BIT 128u
#define ATTR_FLAG_TRANSITIVE_BIT 64u
#define ATTR_FLAG_PARTIAL_BIT 32u
#define ATTR_FLAGS_EXT_LEN_BIT 16u

#define set_flag(attr, flag) ((attr)->flags |= (flag))
#define unset_flag(attr, flag) ((attr)->flags &= ~(flag))


#endif //PLUGINIZED_FRR_XBGP_UBPF_ATTR_H