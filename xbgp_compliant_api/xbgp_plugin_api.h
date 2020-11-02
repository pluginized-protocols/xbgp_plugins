//
// xBGP API
//

#ifndef PLUGINIZED_BIRD_XBGP_API_H
#define PLUGINIZED_BIRD_XBGP_API_H

#include "ubpf_api_common.h"
#include "ubpf_prefix.h"


/**
 * Insertion point that must be
 * implemented on each BGP implementation
 */
enum ubpf_plugins {
    BGP_UNUSED = 0 ,
    BGP_PRE_DECISION,
    BGP_NEXTHOP_RESOLVABLE_DECISION,
    BGP_LOCAL_PREF_DECISION,
    BGP_AS_PATH_LENGTH_DECISION,
    BGP_MED_DECISION, // decision process MED insertion point
    BGP_USE_ORIGIN_DECISION,
    BGP_PREFER_EXTERNAL_PEER_DECISION,
    BGP_IGP_COST_DECISION,
    BGP_ROUTER_ID_DECISION,
    BGP_IPADDR_DECISION,
    BGP_POST_DECISION,
    BGP_DECODE_ATTR,
    BGP_ENCODE_ATTR,
    BGP_PRE_INBOUND_FILTER,
    BGP_PRE_OUTBOUND_FILTER,
};


enum BGP_ROUTE_TYPE {
    BGP_ROUTE_TYPE_UNDEF = 0,
    BGP_ROUTE_TYPE_NEW,
    BGP_ROUTE_TYPE_OLD,
};

/* REGISTERED ATTRIBUTE ID */

#define RESERVED_ATTR_ID 0
#define ORIGIN_ATTR_ID 1
#define AS_PATH_ATTR_ID 2
#define NEXT_HOP_ATTR_ID 3
#define MULTI_EXIT_DISC_ATTR_ID 4
#define LOCAL_PREF_ATTR_ID 5
#define ATOMIC_AGGREGATE_ATTR_ID 6
#define AGGREGATOR_ATTR_ID 7
#define COMMUNITY_ATTR_ID 8
#define ORIGINATOR_ID_ATTR_ID 9
#define CLUSTER_LIST_ATTR_ID 10
#define MP_REACH_NLRI_ATTR_ID 14
#define MP_UNREACH_NLRI_ATTR_ID 15
#define EXTENDED_COMMUNITIES_ATTR_ID 16
#define AS4_PATH_ATTR_ID 17
#define AS4_AGGREGATOR_ATTR_ID 18
#define PMSI_TUNNEL_ATTR_ID 22
#define TUNNEL_ENCAPSULATION_ATTRIBUTE_ATTR_ID 23
#define TRAFFIC_ENGINEERING_ATTR_ID 24
#define IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITY_ATTR_ID 25
#define AIGP_ATTR_ID 26
#define PE_DISTINGUISHER_LABELS_ATTR_ID 27
#define BGPLS_ATTRIBUTE_ATTR_ID 29
#define LARGE_COMMUNITY_ATTR_ID 32
#define BGPSEC_PATH_ATTR_ID 33
#define BGP_COMMUNITY_CONTAINER_ATTRIBUTE_TEMPORARY_REGISTERED_20170728_ATTR_ID 34
#define ONLY_TO_CUSTOMER_OTC_TEMPORARY_REGISTERED_20180329_ATTR_ID 35
#define BGP_DOMAIN_PATH_DPATH_TEMPORARY_REGISTERED_20190708_ATTR_ID 36
#define SFP_ATTRIBUTE_ATTR_ID 37
#define BGP_PREFIXSID_ATTR_ID 40
#define ATTR_SET_ATTR_ID 128

/**
 * Adds a new attribute to the route processed by the current plugin
 * @param code The number that identify the attribute type
 * @param flags Describe the nature of the attribute and how to process it.
 *              x000 0000  Optional bit (1 if optional 0 if required, e.g. AS-PATH)
 *              0x00 0000  Transitive bit (1 if the attribute should be passed to the next
 *                                         BGP if it is not recognized by the BGP implementation)
 *              00x0 0000  Partial bit (1 if a partial attribute has passed one or more router
 *                                      that did not implement the attribute)
 *              000x 0000  Extended length bit (1 if length field is 16 bits, 0 if 8 bits)
 * @param length the actual length of the data contained in decoded_attr. If length > 255,
 *               the Extended length bit must be set to 1
 * @param decoded_attr Buffer containing the new decoded attribute to the
 * @return  0 if the attribute has been stored to the list of attribute of the current BGP route
 *         -1 if the attribute has not been stored.
 */
extern int add_attr(uint code, uint flags, uint16_t length, uint8_t *decoded_attr);

/**
 * Adds or modifies an attribute of the current route. See add_attr for a full explanation.
 * Unlike add_attr, this function can modify an already stored attribute
 * @param attr structure representing the attribute to alter/add
 * @return  0 if the attribute has been stored to the list of attribute of the current BGP route
 *         -1 if the attribute has not been stored.
 */
extern int set_attr(struct path_attribute *attr);

/**
 * Get the current attribute to be processed (if the plugin receives a single
 * attribute as argument)
 * This function is used
 * @return NULL if the attribute cannot be retrieved and passed to the
 *         Otherwise a pointer (pointing to a valid memory space of the plugin) to the structure
 *         of the retreived attribute.
 */
extern struct path_attribute *get_attr();


/**
 * Writes the content of a buffer pointer by ptr to the protocol buffer
 * Usually used when the plugin wants to encode a BGP message to be sent
 * through the network. The buffer must be encoded in network byte order
 *
 * @param ptr, the buffer to be copied to the network buffer
 * @param len length of the buffer to be copied
 * @return  0 if ptr has been successfully copied to the network buffer
 *         -1 if nothing has been done
 */
extern int write_to_buffer(uint8_t *ptr, size_t len);

/**
 * Gets the route attribute from its code if the plugin is handling a given BGP route
 * (Decision process or inside import, export filter)
 * @param code The number that identifies the attribute type to retrieve to the list
 *             of attribute to the route
 * @return NULL if no attribute with the specified code exists or if there is no space to
 *              to copy the attribute inside the plugin memory space
 *              Or a pointer to the memory space allocated for the attribute.
 */
extern struct path_attribute *get_attr_from_code(uint8_t code);

/**
 * Announce to the peer implementation that a prefix has been parsed.
 * This function could only be used when a BGP UPDATE is decoded.
 * @param pfx the prefix to announce to the host BGP implementation
 * @return 1 if the host has correctly received the prefix
 *         0 otherwise. The prefix has not been taken into account
 */
extern int announce_nrli(union ubpf_prefix *pfx);

/**
 * Retrieves the information related to the peer the local router will announce
 * a BGP message.
 * @return NULL if the function is unable to retrieve this data
 *         Otherwise the pointer to a structure is returned.
 *
 *         This function returns a structure of the following form:
 *
 *         struct ubpf_peer_info {
 *           uint32_t as;           // as number of the peer
 *           uint32_t router_id;    // router identifier
 *           uint32_t capability;   // which capability the router is supporting
 *           uint8_t peer_type;     // iBGP, eBGP, or LOCAL for local_bgp_sessions field.
 *
 *           struct {
 *             uint8_t af;                // AF_INET and AF_INET6 for an IPv4 and IPv6 address respectively
 *               union {
 *                 struct in6_addr in6;
 *                 struct in_addr in;
 *             } addr;
 *           } addr;
 *
 *           struct ubpf_peer_info *local_bgp_session; // information about the local router
 *         };
 *
 */
extern struct ubpf_peer_info *get_peer_info(int *nb_peers);

/**
 * Retrieves the information related to the peer having advertised a BGP message to the
 * local router. Do not be mistaken with get_peer_info() that retrieve the information
 * of the peer to WHICH THE LOCAL ROUTER will advertise a BGP message
 *
 * See get_src_peer_info() for a wider explanation
 *
 * @return NULL if the function is unable to pass those data to the plugin
 *         Otherwise a pointer is returned
 */
extern struct ubpf_peer_info *get_src_peer_info();

/**
 * Modifies the information the local BGP router maintains for a peer.
 * @param router_id identifies the peer
 * @param key, key related to which data to alter
 * @param value the value to add
 * @param len length of the value
 * @return 0 if the operation succeeds, -1 in case of failure.
 */
extern int set_peer_info(uint32_t router_id, int key, void *value, int len);


/**
 * Retrieves the current prefix that the router is processing
 * @return the current prefix that is processed
 *         NULL otherwise
 */
extern union ubpf_prefix *get_prefix();

/**
 * Get data related to the nexthop of a given route contained in the Loc-RIB
 * @param pfx If pfx is not NULL, the function retrieve data associated to the
 *            prefix pfx in the Loc-RIB. If pfx is NULL, the function retreive
 *            the nexthop info of the route currently processed by the insertion
 *            point
 * @return The nexthop of the route. May return NULL if the function cannot
 *         retrieve data.
 */
extern struct ubpf_nexthop *get_nexthop(union ubpf_prefix *pfx);

/**
 * Functions to access an entry of the multiple RIBs that BGP maintains
 * @param af_family whether IPv4 or IPv6 prefix (unicast only for at that time)
 * @param pfx prefix of the route to check
 * @return NULL if no entry is related to the prefix. Otherwise, returns data related
 *         to the entry maintained by the protocol.
 */
extern struct ubpf_rib_entry *get_rib_in_entry(uint8_t af_family, union ubpf_prefix *pfx);

extern struct ubpf_rib_entry *get_rib_out_entry(uint8_t af_family, union ubpf_prefix *pfx);

extern struct ubpf_rib_entry *get_loc_rib_entry(uint8_t af_family, union ubpf_prefix *pfx);

/**
 * Retrieve the current BGP route being processed in the insertion point
 *
 * @param which_route Given the Insertion point (and if multiple route are involved), select the route to be
 *                    loaded in the VM.
 * @return The BGP route
 */
extern struct bgp_route *get_bgp_route(enum BGP_ROUTE_TYPE type);

#endif //PLUGINIZED_BIRD_XBGP_API_H

