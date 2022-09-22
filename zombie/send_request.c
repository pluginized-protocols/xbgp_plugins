#ifndef SEND_REQUEST_C
#define SEND_REQUEST_C
#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../prove_stuffs/prove.h"
#define USE_ROUTE
#include "common_zombie.h"

#ifndef PROVERS_T2
#include "my_for.c"
#else
unsigned long my_for(uint8_t* buf, struct pf* pf_cur, struct host* host_cur);
#include <string.h>
#endif

T2SI void send_request()
{
    // allocation of the buffer which will store the request message
    uint8_t* buf = ctx_malloc(4096-19);
    CREATE_BUFFER(buf, 4096-19);
    struct host* host_cur = (struct host*) space;
    struct pf* pf_cur;
    PROOF_T2_INSTS(
            int n_h = 0;
            int n_p = 0;
    )
    do { // iterate on the different peers
        pf_cur = host_cur->first;
        do { // iterate on the different messages for the same peer (to avoid len(bgp message)>4096)
            char prefix_addr[52];
            unsigned long i = my_for(buf, pf_cur, host_cur);
            struct bgp_message msg = {.type = TYPE_REQUEST, .buf_len = i, .buf = buf};
            PROOF_T2_INSTS(
                    memset(prefix_addr, 0, sizeof(prefix_addr)); // using memset instead of a for loop
            )
            NOT_T2(
                    for (int j = 0 ; j < (int) sizeof(prefix_addr) ; j++)
                        prefix_addr[j] = 0;
            )
                ebpf_inet_ntop((uint8_t*)&(host_cur->h->addr.addr), host_cur->h->addr.af, prefix_addr, sizeof(prefix_addr));
            CHECK_BUFFER(buf, msg.buf_len);
            schedule_bgp_message(TYPE_REQUEST, &msg, prefix_addr);
        } while (nextPref(host_cur, &pf_cur) PROOF_T2_INSTS(&& n_p++ < 4096)); // adding explicit bound
    } while (nextHost(&host_cur) PROOF_T2_INSTS(&& n_h++ < 4096)); // adding explicit bound

    reinit();
    ctx_free(buf);
}
#endif