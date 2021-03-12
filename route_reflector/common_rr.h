//
// Created by thomas on 19/05/20.
//

#ifndef PLUGINIZED_BIRD_COMMON_RR_H
#define PLUGINIZED_BIRD_COMMON_RR_H

#define ORIGINATOR_ID 9
#define CLUSTER_LIST 10

enum {
    KEY_RR_CLIENT = 1,
};

#define max_info 65535

static __always_inline int is_rr_client(uint32_t router_id) {

    struct global_info info;
    struct global_info current_client;
    int i;
    struct in_addr rter_id;

    if (get_extra_info("rr_clients", &info) != 0) {
        ebpf_print("Unable to get rr_client manifest key\n");
        return -1;
    }

    for (i = 0; i < max_info ; i++) {
        if (get_extra_info_lst_idx(&info, i, &current_client) != 0) return 0;
        if (get_extra_info_value(&current_client, &rter_id, sizeof(rter_id)) != 0)  {
            ebpf_print("Unable to retrieve router_id of rr clients\n");
            return -1;
        }

        if (router_id == ebpf_ntohl(rter_id.s_addr)) return 1;
    }
    return 0;
}

#endif //PLUGINIZED_BIRD_COMMON_RR_H
