#include <stdint.h>
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../xbgp_compliant_api/xbgp_defs.h"

#include "../prove_stuffs/prove.h"

PROOF_INSTS(
        int nondet_int(void);
        uint16_t nondet_u16(void);

        void free_bgp_route(struct bgp_route *rte) {
            if (!rte) return;

            if (rte->attr) {
                for (int i = 0; i < rte->attr_nb; i++) {
                    if (rte->attr[i]) {
                        free(rte->attr[i]);
                    }
                }
                free(rte->attr);
            }

            free(rte);
        }

        struct bgp_route *get_bgp_route(enum BGP_ROUTE_TYPE type) {
            size_t offset = 0;
            uint8_t *data;
            struct bgp_route *rte;
            int nb_attr;
            if (type != BGP_ROUTE_TYPE_NEW && type != BGP_ROUTE_TYPE_OLD) {
                return NULL;
            }

            nb_attr = nondet_int() % 20;
            if (nb_attr <= 0) return NULL;
            if (nb_attr > 20) return NULL;

            rte = malloc(sizeof(struct bgp_route));
            if (!rte) { return NULL; }

            rte->attr = calloc(nb_attr, sizeof(struct path_attribute *));

            if (!rte->attr) {
                free(rte);
                return NULL;
            }


            rte->attr_nb = nb_attr;

            /* reserve space for attributes */
            for (int i = 0; i < nb_attr; i++) {
                uint16_t attr_len = nondet_u16();
                if (attr_len > 4096) {
                    free_bgp_route(rte);
                    return NULL;
                }
                rte->attr[i] = malloc(sizeof(struct path_attribute) + attr_len);
                if (!rte->attr[i]) {
                    free_bgp_route(rte);
                    return NULL;
                }
                rte->attr[i]->length = attr_len;
            }

            return rte;
        }
)

/* starting point */
uint64_t decision_process_add(args_t *args UNUSED);

#define get_community_from_array(arr, len, attr_id) ({ \
 int i__;                                              \
 struct path_attribute *attr = NULL;                   \
 for (i__ = 0; i__ < (len); i__++) {                   \
     if ((arr)[i__]->code == (attr_id)) {               \
         attr = ((arr)[i__]);                         \
         break;                                        \
     }                                                 \
 }                                                     \
 attr;                                                 \
})

#define check_community(arr, len, community) ({              \
  unsigned int i__;                                          \
  uint16_t val_ret__ = 0;                                    \
  uint32_t commu__;                                          \
  uint32_t *arru32 = (uint32_t *) (arr);                     \
  for (i__ = 0; i__ < (len)/4; i__++) {                      \
      commu__ = ebpf_ntohl(arru32[i__]);                     \
      if ((commu__ >> 16u) == (community)) {                 \
          val_ret__ = commu__ & (0x0000FFFFU);               \
          break;                                             \
      }                                                      \
  }                                                          \
  val_ret__;                                                 \
})

#define TIDYING() \
PROOF_INSTS( do {            \
    if (rte_new) free_bgp_route(rte_new); \
    if (rte_old) free_bgp_route(rte_old); \
} while(0);)


uint64_t decision_process_add(args_t *args UNUSED) {
    uint64_t ret_val;
    struct bgp_route *rte_new;
    struct bgp_route *rte_old;

    struct path_attribute *new_attr;
    struct path_attribute *old_attr;

    uint32_t old_community;
    uint32_t new_community;

    /* retrieve routes from the BGP implementation */
    rte_new = get_bgp_route(BGP_ROUTE_TYPE_NEW);
    rte_old = get_bgp_route(BGP_ROUTE_TYPE_OLD);

    if (!rte_new || !rte_old) {
        TIDYING();
        return BGP_ROUTE_TYPE_FAIL;
    }

    // get the community attribute
    new_attr = get_community_from_array(rte_new->attr, rte_new->attr_nb, COMMUNITY_ATTR_ID);
    old_attr = get_community_from_array(rte_old->attr, rte_old->attr_nb, COMMUNITY_ATTR_ID);

    if (!new_attr || !old_attr) {
        TIDYING();
        return BGP_ROUTE_TYPE_FAIL;
    }

    // get the community value
    new_community = check_community(new_attr->data, new_attr->length, 125);
    old_community = check_community(old_attr->data, old_attr->length, 125);

    ret_val = (new_community > old_community) ? BGP_ROUTE_TYPE_NEW :
              (new_community < old_community) ? BGP_ROUTE_TYPE_FAIL :
              BGP_ROUTE_TYPE_UNKNOWN;

    TIDYING();
    return ret_val;
}

PROOF_INSTS(
        int main(void) {
            uint64_t ret;
            args_t args = {};

            ret = decision_process_add(&args);

            p_assert(ret == BGP_ROUTE_TYPE_UNKNOWN ||
                     ret == BGP_ROUTE_TYPE_NEW ||
                     ret == BGP_ROUTE_TYPE_OLD ||
                     ret == BGP_ROUTE_TYPE_FAIL);

            return 0;
        }
)