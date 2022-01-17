
#ifndef __XBGP_API_VARS_H
#define __XBGP_API_VARS_H

#include "xbgp_plugin_host_api.h"
#include "xbgp_defs.h"
#include "xbgp_api_function_helper.h"

// announce nlri + loc_rib...

static proto_ext_fun_t api_funcs[] = {
        {.fn = add_attr, .name="add_attr", .attributes=HELPER_ATTR_WRITE | HELPER_ATTR_USR_PTR},
        {.fn = set_attr, .name="set_attr", .attributes=HELPER_ATTR_WRITE | HELPER_ATTR_USR_PTR},
        {.fn = get_attr, .name="get_attr", .attributes=HELPER_ATTR_READ},
        {.fn = write_to_buffer, .name="write_to_buffer", .attributes=HELPER_ATTR_WRITE | HELPER_ATTR_USR_PTR},
        {.fn = get_peer_info, .name = "get_peer_info", .attributes=HELPER_ATTR_READ},
        {.fn = get_src_peer_info, .name = "get_src_peer_info", .attributes=HELPER_ATTR_READ},
        {.fn = set_peer_info, .name = "set_peer_info", .attributes=HELPER_ATTR_WRITE},
        {.fn = get_attr_from_code, .name = "get_attr_from_code", .attributes=HELPER_ATTR_READ},
        {.fn = get_attr_from_code_by_route, .name = "get_attr_from_code_by_route", .attributes=HELPER_ATTR_READ},
        {.fn = get_prefix, .name = "get_prefix", .attributes=HELPER_ATTR_READ},
        {.fn = get_nexthop, .name = "get_nexthop", .attributes=HELPER_ATTR_READ},
        {.fn = get_bgp_route, .name = "get_bgp_route", .attributes=HELPER_ATTR_READ},
        {.fn = get_rib_out_entry, .name = "get_rib_out_entry", .attributes=HELPER_ATTR_READ},
        {.fn = new_rib_iterator, .name = "new_rib_iterator", .attributes=HELPER_ATTR_NONE},
        {.fn = rib_has_route, .name = "rib_has_route", .attributes=HELPER_ATTR_READ},
        {.fn = rib_iterator_clean, .name = "rib_iterator_clean", .attributes=HELPER_ATTR_READ},
        {.fn = next_rib_route, .name = "next_rib_route", .attributes=HELPER_ATTR_READ},
        {.fn = remove_route_from_rib, .name = "remove_route_from_rib", .attributes=HELPER_ATTR_READ},
        {.fn = get_vrf, .name = "get_vrf", .attributes=HELPER_ATTR_READ},
        {.fn = schedule_bgp_message, .name = "schedule_bgp_message", .attributes=HELPER_ATTR_WRITE},
        {.fn = peer_session_reset, .name = "peer_session_reset", .attributes=HELPER_ATTR_READ | HELPER_ATTR_WRITE},
        proto_ext_func_null,
};

static insertion_point_info_t insertion_points[] = {
        {.insertion_point_str="bgp_pre_decision", .insertion_point_id = BGP_PRE_DECISION},
        {.insertion_point_str="bgp_nexthop_resolvable_decision", .insertion_point_id = BGP_NEXTHOP_RESOLVABLE_DECISION},
        {.insertion_point_str="bgp_local_pref_decision", .insertion_point_id = BGP_LOCAL_PREF_DECISION},
        {.insertion_point_str="bgp_as_path_length_decision", .insertion_point_id = BGP_AS_PATH_LENGTH_DECISION},
        {.insertion_point_str="bgp_med_decision", .insertion_point_id = BGP_MED_DECISION},
        {.insertion_point_str="bgp_use_origin_decision", .insertion_point_id = BGP_USE_ORIGIN_DECISION},
        {.insertion_point_str="bgp_prefer_external_peer_decision", .insertion_point_id = BGP_PREFER_EXTERNAL_PEER_DECISION},
        {.insertion_point_str="bgp_igp_cost_decision", .insertion_point_id = BGP_IGP_COST_DECISION},
        {.insertion_point_str="bgp_router_id_decision", .insertion_point_id = BGP_ROUTER_ID_DECISION},
        {.insertion_point_str="bgp_ipaddr_decision", .insertion_point_id = BGP_IPADDR_DECISION},
        {.insertion_point_str="bgp_pre_decision", .insertion_point_id = BGP_POST_DECISION},
        {.insertion_point_str="bgp_decode_attr", .insertion_point_id = BGP_DECODE_ATTR},
        {.insertion_point_str="bgp_encode_attr", .insertion_point_id = BGP_ENCODE_ATTR},
        {.insertion_point_str="bgp_pre_inbound_filter", .insertion_point_id = BGP_PRE_INBOUND_FILTER},
        {.insertion_point_str="bgp_pre_outbound_filter", .insertion_point_id = BGP_PRE_OUTBOUND_FILTER},
        {.insertion_point_str="bgp_decode_message", .insertion_point_id = BGP_DECODE_MESSAGE},
        insertion_point_info_null
};

#endif // __XBGP_API_VARS_H
