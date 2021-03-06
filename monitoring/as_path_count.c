//
// Created by thomas on 12/02/21.
//

#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../prove_stuffs/prove.h"


#include <string.h>

#define max_bgp_msg UINT16_MAX

/* (min =  2 bytes for header + 4 bytes one AS) */
#define MIN_SEGMENT_SIZE 6

#ifdef PROVERS
void *get_arg(unsigned int id) {

    unsigned int *length;
    unsigned int *code;
    unsigned char *buf;

    switch (id) {
        case ARG_LENGTH:
            length = malloc(sizeof(*length));
            *length = 18; // to be aligned with the buffer returned in arg_data
            return length;
        case ARG_CODE:
            code = malloc(sizeof(*code));
            *code = AS_PATH_ATTR_ID;
            return code;
        case ARG_DATA:
            buf = malloc(18); // 18bytes 2 hdr + 4*4 bytes
            buf[0] = 2; //as sequence
            buf[1] = 4; // 4 as in the PATH

            // helps cbmc to finish the proof ?
            /*uint32_t super_array[] = {
                56, 97, 53, 1268
            };
            memcpy(buf + 2,  super_array, sizeof(super_array));*/

            return buf;
        default:
            return NULL;
    }
}

#include "../prove_stuffs/mod_ubpf_api.c"
#endif

unsigned int __always_inline count_nb_as(const unsigned char *const as_path, unsigned int max_len) {
    unsigned int i = 0;
    unsigned char segment_length;
    unsigned int nb_as = 0;
    unsigned int tmp;

    if (max_len > max_bgp_msg) return -1;
    if (max_len < MIN_SEGMENT_SIZE) return -1; /*1771bis 4.3b: seg length contains one or more AS */

    if (max_len % 2) return -1;

    unsigned int j = 0; // dummy variable that helps T2 to prove the termination

    while (i < max_len && j < max_len) {
        if (max_len - i <= 2) return UINT32_MAX;

        // if the as_path buffer contains erroneous data,
        // "j" helps to prevent infinite loop by incrementing
        // j by MIN_SEGMENT_SIZE, by eventually leaving the loop
        j += MIN_SEGMENT_SIZE;

        segment_length = as_path[i + 1];
        nb_as += segment_length;

        tmp = (segment_length * 4) + 2;

        if ((((tmp + i) > max_len)
             || (segment_length <= 0)) != 0)
            return UINT32_MAX;

        i += tmp;
    }

    return nb_as;
}

uint64_t count_as_path(args_t *args UNUSED) {
    unsigned int as_number = 0;
    unsigned int *attribute_code = get_arg(ARG_CODE);
    unsigned int *as_path_len = get_arg(ARG_LENGTH);
    unsigned char *as_path = get_arg(ARG_DATA);

    if (!as_path || !as_path_len || !attribute_code) {
        // unable to fetch data from host implementation
        return EXIT_FAILURE;
    } else if (*attribute_code != AS_PATH_ATTR_ID) {
        return EXIT_FAILURE;
    }

    // core part of the plugin
    as_number = count_nb_as(as_path, *as_path_len);

    if (as_number == UINT32_MAX) return EXIT_FAILURE;

    // log the message. If it fails, returns error code
    if (log_msg(L_INFO "as_count:%d\n", LOG_UINT(as_number)) != 0) {
        return EXIT_FAILURE;
    }

#ifdef PROVERS
    // free to be removed
    free(attribute_code);
    free(as_path_len);
    free(as_path);
#endif

    return EXIT_SUCCESS;
}

#ifdef PROVERS
int main(void) {
    args_t args = {};
    count_as_path(&args);
    return 0;
}
#endif