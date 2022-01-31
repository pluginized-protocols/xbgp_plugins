//
// Created by thomas on 29/11/21.
//

#ifndef XBGP_PLUGINS_XBGP_COMMON_H
#define XBGP_PLUGINS_XBGP_COMMON_H

#define LO_RESERVED_RETURN_VAL 0
#define HI_RESERVED_RETURN_VAL 255

/* attribute for helper functions */
#define HELPER_ATTR_NONE 0
#define HELPER_ATTR_USR_PTR 1
#define HELPER_ATTR_WRITE 2
#define HELPER_ATTR_READ 4
#define HELPER_ATTR_MASK 7

typedef struct context context_t;

#endif //XBGP_PLUGINS_XBGP_COMMON_H
