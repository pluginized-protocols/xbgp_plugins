//
// Created by thomas on 20/05/20.
//

#include <stdint.h>
#include <bytecode_public.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "common_ext_comm.h"
//#include "../prove_stuffs/seahorn_api.h"
void *memset(void *s, int c, size_t n);

uint64_t generic_encode_attr(args_t *args __attribute__((unused)));

//#define PROVERS
#include "../prove_stuffs/prove.h"


#ifdef PROVERS

#define next() return 0

struct path_attribute *get_attr(void);

void set_data(void *data);

struct path_attribute *get_attr() {

    struct path_attribute *p_attr;
    p_attr = malloc(sizeof(*p_attr) + 64);

    if (p_attr == NULL) return NULL;

    p_attr->flags = ATTR_OPTIONAL | ATTR_TRANSITIVE;
    p_attr->code = EXTENDED_COMMUNITIES_ATTR_ID;
    p_attr->length = 64;
    set_data(p_attr->data);

    return p_attr;
}
#endif

#ifdef PROVERS_SH
#include "../prove_stuffs/mod_ubpf_api.c"
#endif

uint64_t generic_encode_attr(args_t *args __attribute__((unused))) {

    uint32_t counter = 0;
    uint8_t *attr_buf;
    uint16_t tot_len = 0;
    uint64_t *ext_communities;
    int i;

    struct path_attribute *attribute;
    attribute = get_attr();

    if (!attribute) return 0;

    if (attribute->code != EXTENDED_COMMUNITIES) next();

    tot_len += 2; // Type hdr
    tot_len += attribute->length < 256 ? 1 : 2; // Length hdr
    tot_len += attribute->length;

    attr_buf = ctx_calloc(1, tot_len);
    if (!attr_buf) return 0;

    attr_buf[counter++] = attribute->flags;
    attr_buf[counter++] = attribute->code;

    if (attribute->length < 256) attr_buf[counter++] = (uint8_t) attribute->length;
    else {
        attr_buf[counter] = attribute->length;
        counter += 2;
    }

    ext_communities = (uint64_t *) attribute->data;
    //assume(attribute->length <= 4096u);
    for (i = 0;  i < attribute->length/8 && i < 512; i++) {
        *((uint64_t *)(attr_buf + counter)) = ebpf_htonll(ext_communities[i]);
        counter += 8;
    }

    if(counter != tot_len) {
        ebpf_print("Size mismatch\n");
        return 0;
    }

#ifdef PROVERS
    BUF_CHECK_EXTENDED_COMMUNITY(attr_buf, attribute->length);
#endif


    if (write_to_buffer(attr_buf, counter) == -1) return 0;

    //ctx_free(attr_buf);
    return counter;
}