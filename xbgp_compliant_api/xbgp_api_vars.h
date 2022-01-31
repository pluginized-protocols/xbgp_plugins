
#ifndef __XBGP_API_VARS_H
#define __XBGP_API_VARS_H

#include "xbgp_plugin_host_api.h"
#include "xbgp_defs.h"
#include "xbgp_api_function_helper.h"

// announce nlri + loc_rib...

static xbgp_def_fun_api(add_attr, int, *(uint8_t *) XBGP_ARGS[0], *(uint8_t *) XBGP_ARGS[1],
                        *(uint16_t *) XBGP_ARGS[2], *(uint8_t **) XBGP_ARGS[3]);

static xbgp_def_fun_api(set_attr, int, *(struct path_attribute **) XBGP_ARGS[0]);

static xbgp_def_fun_api(get_attr, struct path_attribute *);

static xbgp_def_fun_api(write_to_buffer, int, *(uint8_t **) XBGP_ARGS[0], *(size_t *) XBGP_ARGS[1]);

static xbgp_def_fun_api(get_peer_info, struct ubpf_peer_info *, *(int **) XBGP_ARGS[0]);

static xbgp_def_fun_api(get_src_peer_info, struct ubpf_peer_info *);

static xbgp_def_fun_api(set_peer_info, int, *(uint32_t *) XBGP_ARGS[0], *(int *) XBGP_ARGS[1],
                        *(void **) XBGP_ARGS[2], *(int *) XBGP_ARGS[3]);

static xbgp_def_fun_api(get_attr_from_code, struct path_attribute *, *(uint8_t *) XBGP_ARGS[0]);

static xbgp_def_fun_api(get_attr_from_code_by_route, struct path_attribute *, *(uint8_t *) XBGP_ARGS[0],
                        *(int *) XBGP_ARGS[1]);

static xbgp_def_fun_api(get_prefix, struct ubpf_prefix *);

static xbgp_def_fun_api(get_nexthop, struct ubpf_nexthop *, *(struct ubpf_prefix **) XBGP_ARGS[0]);

static xbgp_def_fun_api(get_bgp_route, struct bgp_route *, *(enum BGP_ROUTE_TYPE *) XBGP_ARGS[0]);

static xbgp_def_fun_api(get_rib_out_entry, struct bgp_route *, *(uint8_t *) XBGP_ARGS[0],
                        *(struct ubpf_prefix **) XBGP_ARGS[1], *(struct ubpf_peer_info **) XBGP_ARGS[2]);

static xbgp_def_fun_api(new_rib_iterator, int, *(int *) XBGP_ARGS[0], *(int *) XBGP_ARGS[1]);

static xbgp_def_fun_api(rib_has_route, int, *(unsigned int *) XBGP_ARGS[0]);

static xbgp_def_fun_api_void(rib_iterator_clean, *(unsigned int *) XBGP_ARGS[0]);

static xbgp_def_fun_api(next_rib_route, struct bgp_route *, *(unsigned int *) XBGP_ARGS[0]);

static xbgp_def_fun_api(remove_route_from_rib, int, *(struct ubpf_prefix **) XBGP_ARGS[0],
                        *(struct ubpf_peer_info **) XBGP_ARGS[1]);

static xbgp_def_fun_api(get_vrf, int, *(struct vrf_info **) XBGP_ARGS[0]);

static xbgp_def_fun_api(schedule_bgp_message, int, *(int *) XBGP_ARGS[0],
                        *(struct bgp_message **) XBGP_ARGS[1], *(const char **) XBGP_ARGS[2]);

static xbgp_def_fun_api(peer_session_reset, int, *(const char **) XBGP_ARGS[0]);


static proto_ext_fun_t api_funcs[] = {
        {
                .args_type = (ffi_type *[]) {&ffi_type_uint8, &ffi_type_uint8,
                                             &ffi_type_uint16, &ffi_type_pointer},
                .return_type = &ffi_type_sint,
                .args_nb = 4,
                .fn = add_attr,
                .closure_fn = xbgp_api_name_closure(add_attr),
                .name="add_attr",
                .attributes=HELPER_ATTR_WRITE | HELPER_ATTR_USR_PTR
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_pointer},
                .return_type = &ffi_type_sint,
                .args_nb = 1,
                .fn = set_attr,
                .closure_fn = xbgp_api_name_closure(set_attr),
                .name="set_attr",
                .attributes=HELPER_ATTR_WRITE | HELPER_ATTR_USR_PTR,
        },
        {
                .args_type = NULL,
                .return_type = &ffi_type_pointer,
                .args_nb = 0,
                .fn = get_attr,
                .closure_fn= xbgp_api_name_closure(get_attr),
                .name="get_attr",
                .attributes=HELPER_ATTR_READ,
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_pointer, &ffi_type_uint64},
                .return_type = &ffi_type_sint,
                .args_nb = 2,
                .fn = write_to_buffer,
                .closure_fn = xbgp_api_name_closure(write_to_buffer),
                .name="write_to_buffer",
                .attributes=HELPER_ATTR_WRITE | HELPER_ATTR_USR_PTR
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_pointer},
                .return_type = &ffi_type_pointer,
                .args_nb = 1,
                .fn = get_peer_info,
                .closure_fn = xbgp_api_name_closure(get_peer_info),
                .name = "get_peer_info",
                .attributes=HELPER_ATTR_READ,
        },
        {
                .args_type = NULL,
                .return_type = &ffi_type_pointer,
                .args_nb = 0,
                .fn = get_src_peer_info,
                .closure_fn = xbgp_api_name_closure(get_src_peer_info),
                .name = "get_src_peer_info",
                .attributes=HELPER_ATTR_READ,
        },
        {
                .args_type =  (ffi_type *[]) {&ffi_type_uint32, &ffi_type_sint,
                                              &ffi_type_pointer, &ffi_type_sint},
                .return_type = &ffi_type_sint,
                .args_nb = 4,
                .fn = set_peer_info,
                .closure_fn = xbgp_api_name_closure(set_peer_info),
                .name = "set_peer_info",
                .attributes=HELPER_ATTR_WRITE
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_uint8},
                .return_type = &ffi_type_pointer,
                .args_nb = 1,
                .fn = get_attr_from_code,
                .closure_fn = xbgp_api_name_closure(get_attr_from_code),
                .name = "get_attr_from_code",
                .attributes=HELPER_ATTR_READ
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_uint8, &ffi_type_sint},
                .return_type = &ffi_type_pointer,
                .args_nb = 2,
                .fn = get_attr_from_code_by_route,
                .closure_fn = xbgp_api_name_closure(get_attr_from_code_by_route),
                .name = "get_attr_from_code_by_route",
                .attributes=HELPER_ATTR_READ
        },
        {
                .args_type = NULL,
                .return_type = &ffi_type_pointer,
                .args_nb = 0,
                .fn = get_prefix,
                .closure_fn = xbgp_api_name_closure(get_prefix),
                .name = "get_prefix",
                .attributes=HELPER_ATTR_READ
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_pointer},
                .return_type = &ffi_type_pointer,
                .args_nb = 1,
                .fn = get_nexthop,
                .closure_fn = xbgp_api_name_closure(get_nexthop),
                .name = "get_nexthop",
                .attributes=HELPER_ATTR_READ
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_sint},
                .return_type = &ffi_type_pointer,
                .args_nb = 1,
                .fn = get_bgp_route,
                .closure_fn = xbgp_api_name_closure(get_bgp_route),
                .name = "get_bgp_route",
                .attributes=HELPER_ATTR_READ},
        {
                .args_type = (ffi_type *[]) {&ffi_type_uint8, &ffi_type_pointer, &ffi_type_pointer},
                .return_type = &ffi_type_pointer,
                .args_nb = 3,
                .fn = get_rib_out_entry,
                .closure_fn = xbgp_api_name_closure(get_rib_out_entry),
                .name = "get_rib_out_entry",
                .attributes=HELPER_ATTR_READ
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_sint, &ffi_type_sint},
                .return_type = &ffi_type_sint,
                .args_nb = 2,
                .fn = new_rib_iterator,
                .closure_fn = xbgp_api_name_closure(new_rib_iterator),
                .name = "new_rib_iterator",
                .attributes=HELPER_ATTR_NONE
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_uint},
                .return_type = &ffi_type_sint,
                .args_nb = 1,
                .fn = rib_has_route,
                .closure_fn = xbgp_api_name_closure(rib_has_route),
                .name = "rib_has_route",
                .attributes=HELPER_ATTR_READ
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_uint},
                .return_type = &ffi_type_void,
                .args_nb = 1,
                .fn = rib_iterator_clean,
                .closure_fn = xbgp_api_name_closure(rib_iterator_clean),
                .name = "rib_iterator_clean",
                .attributes=HELPER_ATTR_READ
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_uint},
                .return_type = &ffi_type_pointer,
                .args_nb = 1,
                .fn = next_rib_route,
                .closure_fn = xbgp_api_name_closure(next_rib_route),
                .name = "next_rib_route",
                .attributes=HELPER_ATTR_READ
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_pointer, &ffi_type_pointer},
                .return_type = &ffi_type_sint,
                .args_nb = 2,
                .fn = remove_route_from_rib,
                .closure_fn = xbgp_api_name_closure(remove_route_from_rib),
                .name = "remove_route_from_rib",
                .attributes=HELPER_ATTR_READ
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_pointer},
                .return_type = &ffi_type_sint,
                .args_nb = 1,
                .fn = get_vrf,
                .closure_fn = xbgp_api_name_closure(get_vrf),
                .name = "get_vrf",
                .attributes=HELPER_ATTR_READ
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_sint, &ffi_type_pointer, &ffi_type_pointer},
                .return_type = &ffi_type_sint,
                .args_nb = 3,
                .fn = schedule_bgp_message,
                .closure_fn = xbgp_api_name_closure(schedule_bgp_message),
                .name = "schedule_bgp_message",
                .attributes=HELPER_ATTR_WRITE
        },
        {
                .args_type = (ffi_type *[]) {&ffi_type_pointer},
                .return_type = &ffi_type_sint,
                .args_nb = 1,
                .fn = peer_session_reset,
                .closure_fn = xbgp_api_name_closure(peer_session_reset),
                .name = "peer_session_reset",
                .attributes=HELPER_ATTR_READ | HELPER_ATTR_WRITE},
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
