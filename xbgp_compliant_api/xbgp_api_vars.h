
#ifndef __XBGP_API_VARS_H
#define __XBGP_API_VARS_H

static proto_ext_fun_t funcs[] = {
        {.fn = add_attr, .name="add_attr"},
        {.fn = set_attr, .name="set_attr"},
        {.fn = get_attr, .name="get_attr"},
        {.fn = write_to_buffer, .name="write_to_buffer"},
        {.fn = get_attr_by_code_from_rte, .name = "get_attr_by_code_from_rte"},
        {.fn = get_peer_info, .name = "get_peer_info"},
        {.fn = get_src_peer_info, .name = "get_src_peer_info"},
        {.fn = set_peer_info_src, .name = "set_peer_info_src"},
        {.fn = set_peer_info, .name = "set_peer_info"},
        {.fn = get_peer_info_src_extra, .name = "get_peer_info_src_extra"},
        {.fn = get_peer_info_extra, .name = "get_peer_info_src_extra"},
        {.fn = get_attr_from_code, .name = "get_attr_from_code"},
        {.fn = get_prefix, .name = "get_prefix"},
        proto_ext_func_null,
};

static plugin_info_t plugins[] = {
        {.plugin_id = BGP_MED_DECISION, .plugin_str="bgp_med_decision"},
        {.plugin_id = BGP_DECODE_ATTR, .plugin_str="bgp_decode_attr"},
        {.plugin_id = BGP_ENCODE_ATTR, .plugin_str="bgp_encode_attr"},
        {.plugin_id = BGP_PRE_INBOUND_FILTER, .plugin_str="bgp_pre_inbound_filter"},
        {.plugin_id = BGP_PRE_OUTBOUND_FILTER, .plugin_str="bgp_pre_outbound_filter"},
        plugin_info_null
};

#endif // __XBGP_API_VARS_H
