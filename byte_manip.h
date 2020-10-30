//
// Created by thomas on 4/06/20.
//

#ifndef PLUGINIZED_BIRD_BYTE_MANIP_H
#define PLUGINIZED_BIRD_BYTE_MANIP_H

#define get_u32(data) \
({ \
    uint32_t a; \
    a = *((uint32_t *) (data)); \
    ebpf_ntohl(a); \
})

#endif //PLUGINIZED_BIRD_BYTE_MANIP_H
