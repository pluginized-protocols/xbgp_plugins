#include "ubpf_api.h"
#include "bytecode_public.h"

#define is_known_attr(code) ( \
    ((code) == RESERVED_ATTR_ID) || \
    ((code) == ORIGIN_ATTR_ID) || \
    ((code) == AS_PATH_ATTR_ID) || \
    ((code) == NEXT_HOP_ATTR_ID) || \
    ((code) == MULTI_EXIT_DISC_ATTR_ID) || \
    ((code) == LOCAL_PREF_ATTR_ID) || \
    ((code) == ATOMIC_AGGREGATE_ATTR_ID) || \
    ((code) == AGGREGATOR_ATTR_ID) || \
    ((code) == COMMUNITY_ATTR_ID) || \
    ((code) == ORIGINATOR_ID_ATTR_ID) || \
    ((code) == CLUSTER_LIST_ATTR_ID) || \
    ((code) == MP_REACH_NLRI_ATTR_ID) || \
    ((code) == MP_UNREACH_NLRI_ATTR_ID) || \
    ((code) == EXTENDED_COMMUNITIES_ATTR_ID) || \
    ((code) == AS4_PATH_ATTR_ID) || \
    ((code) == AS4_AGGREGATOR_ATTR_ID) || \
    ((code) == PMSI_TUNNEL_ATTR_ID) || \
    ((code) == TUNNEL_ENCAPSULATION_ATTRIBUTE_ATTR_ID) || \
    ((code) == TRAFFIC_ENGINEERING_ATTR_ID) || \
    ((code) == IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITY_ATTR_ID) || \
    ((code) == AIGP_ATTR_ID) || \
    ((code) == PE_DISTINGUISHER_LABELS_ATTR_ID) || \
    ((code) == BGPLS_ATTRIBUTE_ATTR_ID) || \
    ((code) == LARGE_COMMUNITY_ATTR_ID) || \
    ((code) == BGPSEC_PATH_ATTR_ID) || \
    ((code) == BGP_COMMUNITY_CONTAINER_ATTRIBUTE_TEMPORARY_REGISTERED_20170728_ATTR_ID) || \
    ((code) == ONLY_TO_CUSTOMER_OTC_TEMPORARY_REGISTERED_20180329_ATTR_ID) || \
    ((code) == BGP_DOMAIN_PATH_DPATH_TEMPORARY_REGISTERED_20190708_ATTR_ID) || \
    ((code) == SFP_ATTRIBUTE_ATTR_ID) || \
    ((code) == BGP_PREFIXSID_ATTR_ID) || \
    ((code) == ATTR_SET_ATTR_ID))



uint64_t parse_attribute(args_t *args UNUSED) {

    uint8_t *code;
    code = get_arg(0); // argument 0 is the code attribute received from the neighbor

    if (!code) {
        // unable to retrieve the argument (internal failure)
        return EXIT_FAILURE;
    }

    if (!is_known_attr(*code)) {
        return EXIT_FAILURE;
    }

    return 0;
}
