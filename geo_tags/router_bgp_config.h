//
// Created by thomas on 15/05/20.
//

#ifndef PLUGINIZED_BIRD_ROUTER_BGP_CONFIG_H
#define PLUGINIZED_BIRD_ROUTER_BGP_CONFIG_H

#include <stdint.h>

typedef struct geo_tags {
    int32_t coordinates[2];
} geo_tags_t;

static geo_tags_t this_router_coordinate = {.coordinates = {1, 2}};

static __always_inline uint32_t encode_number(int32_t number) {
    if (number >= 0) return number;
    return ((uint32_t)(-number)) | (1u << 31u);
}

static __always_inline uint64_t coord_hton(geo_tags_t *tags) {

    uint64_t _buf;
    uint8_t *buf = (uint8_t *) &_buf;

    *((uint32_t *) buf) = htonl(encode_number(tags->coordinates[0]));
    *((uint32_t *) (buf+4)) = htonl(encode_number(tags->coordinates[1]));

    return _buf;
}

static __always_inline uint64_t coord_to_attr(geo_tags_t *tags) {
    uint64_t _buf;
    uint8_t *buf = (uint8_t *) &_buf;

    *((uint32_t *) buf) = tags->coordinates[0];
    *((uint32_t *) (buf+4)) = tags->coordinates[1];

    return _buf;

}

#endif //PLUGINIZED_BIRD_ROUTER_BGP_CONFIG_H
