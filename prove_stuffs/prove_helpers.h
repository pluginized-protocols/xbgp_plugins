//
// Created by thomas on 31/03/21.
//

#ifndef XBGP_PLUGINS_PROVE_HELPERS_H
#define XBGP_PLUGINS_PROVE_HELPERS_H

#include "../xbgp_compliant_api/xbgp_defs.h"

#define ELEVENTH_ARGUMENT(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, ...) a11

// OPT_ADD automatically add the content of "a" if the next argument of the variadic macro is set
#define OPT_ADD(a, ...) ELEVENTH_ARGUMENT(dummy, ## __VA_ARGS__, a, a, a, a, a, a, a, a, a, , dummy)

#define GEN_ASSERT(attr, attr_code, attr_length, attr_flags, ...) \
    p_assert(                                                  \
            ((attr)->code != (attr_code)) || \
            (                                                \
               ((attr)->length == (attr_length)) && \
               ((attr)->flags == (attr_flags))               \
               OPT_ADD(&&(__VA_ARGS__), ##__VA_ARGS__)\
            ) \
          )

#define BUF_CHECK_LENGTH(buf, length, offset) \
    (((length) <= 255 && (buf)[offset] == (length)) || \
    ((length) > 255 && (*(uint16_t *) ((buf)+(offset))) == (length)))

#define BUF_GEN_ASSERT(buf, code, length, flags, ...) \
    p_assert(                                      \
        ((buf)[1] != (code)) ||                  \
        (                                        \
            (buf)[0] == (flags) &&               \
            BUF_CHECK_LENGTH(buf, length, 2)     \
            OPT_ADD(&&(__VA_ARGS__), ##__VA_ARGS__)         \
        )                                        \
    )


#define CHECK_ORIGIN(p_attr) \
   GEN_ASSERT(p_attr, ORIGIN_ATTR_ID, 1, ATTR_TRANSITIVE, \
      (*(uint8_t *)((p_attr)->data) == 0   ||               \
      *(uint8_t *)((p_attr)->data) == 1   ||               \
      *(uint8_t *)((p_attr)->data) == 2)  \
   )

#define CHECK_ASPATH(p_attr, len) \
    GEN_ASSERT(p_attr, AS_PATH_ATTR_ID, len, ATTR_TRANSITIVE, \
        ((p_attr)->length == (len)) &&                           \
        ((p_attr)->length % 2 == 0))

#define CHECK_NEXTHOP(p_attr) \
    GEN_ASSERT(p_attr, NEXT_HOP_ATTR_ID, 4, ATTR_TRANSITIVE)

#define CHECK_MED(p_attr) \
    GEN_ASSERT(p_attr, MULTI_EXIT_DISC_ATTR_ID, 4, ATTR_OPTIONAL)

#define CHECK_LOCAL_PREF(p_attr) \
    GEN_ASSERT(p_attr, LOCAL_PREF_ATTR_ID, 4, ATTR_TRANSITIVE)

#define CHECK_ATOMIC_AGGR(p_attr) \
    GEN_ASSERT(p_attr, ATOMIC_AGGREGATE_ATTR_ID, 0, ATTR_TRANSITIVE)

#define CHECK_AGGREGATOR(p_attr) \
    GEN_ASSERT(p_attr, AGGREGATOR_ATTR_ID, 6, ATTR_OPTIONAL | ATTR_TRANSITIVE)

#define CHECK_COMMUNITY(p_attr, len) \
    GEN_ASSERT(p_attr, COMMUNITY_ATTR_ID, len, ATTR_OPTIONAL | ATTR_TRANSITIVE, (len) % 4 == 0)

#define CHECK_ORIGINATOR(p_attr) \
    GEN_ASSERT(p_attr, ORIGINATOR_ID_ATTR_ID, 4, ATTR_OPTIONAL)

#define CHECK_CLUSTER_LIST(p_attr, len) \
    GEN_ASSERT(p_attr, CLUSTER_LIST_ATTR_ID, len, ATTR_OPTIONAL, \
        ((len) % 4 == 0) &&             \
        ((p_attr)->length % 4 == 0)                 \
    )

#define CHECK_EXTENDED_COMMUNITY(p_attr, len) \
    GEN_ASSERT(p_attr, EXTENDED_COMMUNITIES_ATTR_ID, len, ATTR_OPTIONAL | ATTR_TRANSITIVE, (len) % 8 == 0)

#define CHECK_AS4_PATH(p_attr, len) \
    GEN_ASSERT(p_attr, AS4_PATH_ATTR_ID, len, ATTR_OPTIONAL | ATTR_TRANSITIVE)

#define CHECK_AS4_AGGREGATOR(p_attr) \
    GEN_ASSERT(p_attr, AS4_AGGREGATOR_ATTR_ID, 4, ATTR_OPTIONAL | ATTR_TRANSITIVE)

// according to RFC 7311 section 3 :
// " When an AIGP attribute is created, it SHOULD contain no more than one
//   AIGP TLV.  However, if it contains more than one AIGP TLV, only the
//   first one is used "
// Hence, the length is variable....
#define CHECK_AIGP(p_attr, len) \
    GEN_ASSERT(p_attr, AIGP_ATTR_ID, len, ATTR_OPTIONAL)

#define CHECK_LARGE_COMMUNITY(p_attr, len) \
    GEN_ASSERT(p_attr, LARGE_COMMUNITY_ATTR_ID, len, ATTR_OPTIONAL | ATTR_TRANSITIVE, \
     (p_attr)->length % 12 == 0                                       \
    )


#define CHECK_ATTR_FORMAT(p_attr, len) do { \
   CHECK_ORIGIN(p_attr);                    \
   CHECK_ASPATH(p_attr, len);               \
   CHECK_NEXTHOP(p_attr);                   \
   CHECK_MED(p_attr);                       \
   CHECK_LOCAL_PREF(p_attr);                \
   CHECK_ATOMIC_AGGR(p_attr);               \
   CHECK_AGGREGATOR(p_attr);                \
   CHECK_COMMUNITY(p_attr, len);            \
   CHECK_ORIGINATOR(p_attr);                \
   CHECK_CLUSTER_LIST(p_attr, len);         \
   CHECK_EXTENDED_COMMUNITY(p_attr, len);   \
   CHECK_AS4_PATH(p_attr,len);              \
   CHECK_AS4_AGGREGATOR(p_attr);            \
   CHECK_AIGP(p_attr, len);                 \
   CHECK_LARGE_COMMUNITY(p_attr, len);      \
} while(0)


#define BUF_CHECK_ORIGIN(buf) \
    BUF_GEN_ASSERT(buf, ORIGIN_ATTR_ID, 1, ATTR_TRANSITIVE, \
      ((buf)[3] == 0 || (buf)[3] == 1 || (buf)[3] == 2))

#define BUF_CHECK_ASPATH(buf, len) \
    BUF_GEN_ASSERT(buf, AS_PATH_ATTR_ID, len, ATTR_TRANSITIVE, (len) % 2 == 0)

#define BUF_CHECK_NEXTHOP(buf) \
    BUF_GEN_ASSERT(buf, NEXT_HOP_ATTR_ID, 4, ATTR_TRANSITIVE)

#define BUF_CHECK_MED(buf) \
    BUF_GEN_ASSERT(buf, MULTI_EXIT_DISC_ATTR_ID, 4, ATTR_OPTIONAL)

#define BUF_CHECK_LOCAL_PREF(buf) \
    BUF_GEN_ASSERT(buf, LOCAL_PREF_ATTR_ID, 4, ATTR_TRANSITIVE)

#define BUF_CHECK_ATOMIC_AGGR(buf) \
    BUF_GEN_ASSERT(buf, ATOMIC_AGGREGATE_ATTR_ID, 0, ATTR_TRANSITIVE)

#define BUF_CHECK_AGGREGATOR(buf) \
    BUF_GEN_ASSERT(buf, AGGREGATOR_ATTR_ID, 6, ATTR_OPTIONAL | ATTR_TRANSITIVE)

#define BUF_CHECK_COMMUNITY(buf, len) \
    BUF_GEN_ASSERT(buf, COMMUNITY_ATTR_ID, len, ATTR_OPTIONAL | ATTR_TRANSITIVE)

#define BUF_CHECK_ORIGINATOR(buf) \
    BUF_GEN_ASSERT(buf, ORIGINATOR_ID_ATTR_ID, 4, ATTR_OPTIONAL)

#define BUF_CHECK_CLUSTER_LIST(buf, len) \
    BUF_GEN_ASSERT(buf, CLUSTER_LIST_ATTR_ID, len, ATTR_OPTIONAL, (len) % 4 == 0)

#define BUF_CHECK_EXTENDED_COMMUNITY(buf, len) \
    BUF_GEN_ASSERT(buf, EXTENDED_COMMUNITIES_ATTR_ID, len, ATTR_OPTIONAL | ATTR_TRANSITIVE, (len) % 8 == 0)

#define BUF_CHECK_AS4_PATH(buf, len) \
    BUF_GEN_ASSERT(buf, AS4_PATH_ATTR_ID, len, ATTR_OPTIONAL | ATTR_TRANSITIVE)

#define BUF_CHECK_AS4_AGGREGATOR(buf) \
    BUF_GEN_ASSERT(buf, AS4_AGGREGATOR_ATTR_ID, 4, ATTR_OPTIONAL | ATTR_TRANSITIVE)

#define BUF_CHECK_LARGE_COMMUNITY(buf, len) \
    BUF_GEN_ASSERT(buf, LARGE_COMMUNITY_ATTR_ID, len, ATTR_OPTIONAL | ATTR_TRANSITIVE, (len) % 12 = 0)

#define BUF_CHECK_AIGP(p_attr, len) \
    BUF_GEN_ASSERT(p_attr, AIGP_ATTR_ID, len, ATTR_OPTIONAL)

#define BUF_CHECK_ATTR_FORMAT(buf, len) do { \
   BUF_CHECK_ORIGIN(buf);                    \
   BUF_CHECK_ASPATH(buf, len);               \
   BUF_CHECK_NEXTHOP(buf);                   \
   BUF_CHECK_MED(buf);                       \
   BUF_CHECK_LOCAL_PREF(buf);                \
   BUF_CHECK_ATOMIC_AGGR(buf);               \
   BUF_CHECK_AGGREGATOR(buf);                \
   BUF_CHECK_COMMUNITY(buf, len);            \
   BUF_CHECK_ORIGINATOR(buf);                \
   BUF_CHECK_CLUSTER_LIST(buf, len);         \
   BUF_CHECK_EXTENDED_COMMUNITY(buf, len);   \
   BUF_CHECK_AS4_PATH(buf,len);              \
   BUF_CHECK_AS4_AGGREGATOR(buf);            \
   BUF_CHECK_AIGP(buf, len);                 \
   BUF_CHECK_LARGE_COMMUNITY(buf, len);      \
} while(0)


#define HI_BOUND(val, hi) ((val) <= (hi))

#define LO_BOUND(val, lo) ((lo) <= (val))

#define IN_BOUNDS(val, lo, hi) (LO_BOUND((val), lo) && HI_BOUND((val), hi))

#define CHECK_IN_BOUNDS_ATTR(p_attr, ATTR_ID, type, lo, hi) \
    p_assert( ((p_attr)->code != (ATTR_ID)) || \
             (IN_BOUNDS(*((type *) (p_attr)->data), lo, hi))                               \
             )

#define CHECK_IN_BOUNDS_LOCAL_PREF(p_attr, lo, hi) \
    CHECK_IN_BOUNDS_ATTR(p_attr, LOCAL_PREF_ATTR_ID, uint32_t, lo, hi)

#define CHECK_IN_BOUNDS_MED(p_attr, lo, hi) \
    CHECK_IN_BOUNDS_ATTR(p_attr, MULTI_EXIT_DISC_ATTR_ID, uint32_t, lo, hi)

#define RET_VAL_FILTERS_CHECK(x) \
    p_assert((x) == PLUGIN_FILTER_REJECT || (x) == PLUGIN_FILTER_ACCEPT || \
    (x) == PLUGIN_FILTER_UNKNOWN)


#endif //XBGP_PLUGINS_PROVE_HELPERS_H
