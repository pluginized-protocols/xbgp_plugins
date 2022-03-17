#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../prove_stuffs/prove.h"


PROOF_INSTS(
        uint8_t nondet_u8(void);
        void *get_arg(unsigned int arg_type) {
            if (arg_type != ARG_CODE) return NULL;

            uint8_t *the_code;
            the_code = malloc(sizeof(*the_code));
            if (!the_code) return NULL;

            *the_code = nondet_u8();
            return the_code;
        }

)

#define TIDYING() \
PROOF_INSTS( do { \
    if (code) free(code);\
} while(0))


/* starting point */
uint64_t reject_unknown_attr(args_t *args UNUSED);

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


uint64_t reject_unknown_attr(args_t *args UNUSED) {

    uint8_t *code;
    code = get_arg(ARG_CODE); // get the argument from its "ID"

    if (!code) {
        // unable to retrieve the argument (internal failure)
        TIDYING();
        return EXIT_FAILURE;
    }

    if (!is_known_attr(*code)) {
        TIDYING();
        return EXIT_FAILURE;
    }

    TIDYING();
    return 0;
}

PROOF_INSTS(
        int main(void) {
            args_t args = {};
            uint64_t ret;

            ret = reject_unknown_attr(&args);

            p_assert(ret == EXIT_FAILURE || ret == EXIT_SUCCESS);
            return ret % UINT16_MAX;
        }
)