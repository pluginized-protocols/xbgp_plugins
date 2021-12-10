//
// Created by thomas on 15/05/20.
//

#ifndef PLUGINIZED_BIRD_ROUTER_BGP_CONFIG_H
#define PLUGINIZED_BIRD_ROUTER_BGP_CONFIG_H

#define BA_GEO_TAG 42
#define PREFIX_ORIGINATOR 43

#include <stdint.h>


/**
 * A geotag uses the decimal representation
 * of a coordinates that goes from -180.0 to
 * 180.0. Plugins represent it at the form
 *
 *   (180 + coordinate_lat_long) * 10^6
 *
 * i.e. we make the coordinate
 * goes through [ 0 ; 360 * 10^6 ]
 *
 * we multiply the coordinate to take the
 * first sixth decimal and then truncate
 * the decimal part. It ensures a precision
 * of 11.1cm (http://wiki.gis.com/wiki/index.php/Decimal_degrees)
 *
 */
typedef struct geo_tags {
    uint32_t coordinates[2];
} geo_tags_t;

#define HI_COORD 360000000
#define LO_COORD 0

#define COORD_PRECISION 6 // this ensures 11.1 cm precision

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static geo_tags_t this_router_coordinate = {.coordinates = {1, 2}};

#define valid_range(x) ({ \
   int __valid_range__ ;     \
   if (LO_COORD <= (x) && (x) <= HI_COORD) { \
       __valid_range__ = 1;                          \
   } else {                  \
       __valid_range__ = 0;                          \
   }                         \
   __valid_range__; \
})


#define valid_coord(geo) ({\
    valid_range(((geo)->coordinates)[0]) && \
    valid_range(((geo)->coordinates)[1]);                    \
})

static __always_inline uint64_t coord_hton(geo_tags_t *tags) {

    uint64_t _buf;
    uint8_t *buf = (uint8_t *) &_buf;

    *((uint32_t *) buf) = ebpf_htonl(tags->coordinates[0]);
    *((uint32_t *) (buf+4)) = ebpf_htonl(tags->coordinates[1]);

    return _buf;
}

static __always_inline uint64_t coord_to_attr(geo_tags_t *tags) {
    uint64_t _buf;
    uint8_t *buf = (uint8_t *) &_buf;

    *((uint32_t *) buf) = tags->coordinates[0];
    *((uint32_t *) (buf+4)) = tags->coordinates[1];

    return _buf;

}

static __always_inline uint64_t euclidean_distance(const struct geo_tags *geo1, const struct geo_tags *geo2) {
    uint64_t a, a_square;
    uint64_t b, b_square;
    uint64_t dist_square;
    const uint32_t *x1;
    const uint32_t *x2;

    if (!geo1 || !geo2) return 0;

    if (!(valid_coord(geo1) && valid_coord(geo2))) {
        return 0;
    }

    x1 = geo1->coordinates;
    x2 = geo2->coordinates;

    a = (MAX(x2[0], x1[0]) - MIN(x2[0], x1[0]));
    b = (MAX(x2[1], x1[1]) - MIN(x2[1], x1[1]));

    a_square = a * a;
    b_square = b * b;

    dist_square = (MAX(a_square, b_square) + MIN(a_square, b_square));
    return ebpf_sqrt(dist_square, COORD_PRECISION);
}

#endif //PLUGINIZED_BIRD_ROUTER_BGP_CONFIG_H
