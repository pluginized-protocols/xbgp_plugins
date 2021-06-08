//
// Created by thomas on 1/04/21.
//

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

int main (void) {
    size_t offset = 0;
    uint8_t my_super_buf[42];
    memset(my_super_buf, 0, sizeof(my_super_buf));

    /* encode type */
    my_super_buf[offset] = 42;
    offset++;

    /* length */
    my_super_buf[offset] = 4;
    offset++;

    /* value */
    *((uint32_t *)(my_super_buf + offset)) = (uint32_t) 42;

    assert(my_super_buf[0] == 42);
    assert(my_super_buf[1] == 4);
    assert(*(uint32_t *)(my_super_buf + 2) >= 40);
    return EXIT_SUCCESS;
}