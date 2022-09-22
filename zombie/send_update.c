#include "../xbgp_compliant_api/xbgp_plugin_api.h"
#include "../prove_stuffs/prove.h"

#include "common_zombie.h"

#define AS_PATH	    0x02
#define NEXT_HOP    0x03
struct ubpf_peer_info* peer;
uint8_t* buf;

/**
 * @return 0 if there is no more prefix in the list, 1 otherwise
 */
T2SI uint64_t send_update(struct host* host_cur, struct pf** pf_cur, struct bgp_route* ure)
{
    PROOF_T2_INSTS(
            memset(buf, 0, 4096-19);
    )
    NOT_T2(
            for (int i = 0 ; i < 4096-19 ; i++)
                buf[i] = 0;
    )
    CREATE_BUFFER(buf, 4096-19);
    size_t attributes_size = 0;
    size_t nlri_size = 0;
    if (ure != NULL)
    {
        for (int i = 0 ; i < ure->attr_nb PROOF_T2_INSTS(&& i < 4096); i++)
        {
            PROOF_T2_INSTS(
                    attributes_size += 4; // minimum increment
                        )
            NOT_T2(
                    attributes_size += ure->attr[i]->length;
                    attributes_size += 3; // size of flag + type + length field
                    attributes_size += ((ure->attr[i]->flags >> 4) & 0b1); // in case of extended length
                    if (ure->attr[i]->code == AS_PATH)
                        attributes_size += 4; //we need to add our AS to the AS-PATH attribute
            )
        }
        nlri_size = 1;
        PROOF_T2_INSTS(
                nlri_size += 1; // prefixlen is striclty > 1
        )
        NOT_T2(
                nlri_size += size_pfx(ure->pfx.prefixlen);
        )
    }
    int i = 2;
    int notEmpty = *pf_cur != next_pref;
    PROOF_T2_INSTS(int bound = 0;)
    while (
            NOT_T2(i < (int)(4096-21-attributes_size-nlri_size))
            PROOF_T2_INSTS(bound++ < 4096)
            && notEmpty
            )
    {
        struct pf* pf = *pf_cur;
        buf[i++] = (uint8_t) pf->pfx->prefixlen;
        PROOF_T2_INSTS(
                memcpy(buf+i, pf->pfx->u, size_pfx(pf->pfx->prefixlen));
	            i += 1; // prefixlen strictly > 0
        )
        NOT_T2(
                for (int j = 0 ; j < (size_pfx(pf->pfx->prefixlen)) ; j++)
                        buf[i++] = pf->pfx->u[j];
        )
        //log_prefix(pf->pfx->prefixlen, buf+i-(size_pfx(pf->pfx->prefixlen)), WITHDRAW);

        notEmpty = nextPrefAndClean(host_cur, pf_cur);
    }
    uint16_t* bufs = (uint16_t*) buf;
    bufs[0] = ebpf_htons((uint16_t)i-2);
    bufs = (uint16_t*) (buf+i);
    bufs[0] = ebpf_htons((uint16_t)attributes_size);
    i+=2;
    if (ure != NULL)
    {
        for (int j = 0 ; j < ure->attr_nb PROOF_T2_INSTS(&& j < 4096); j++)
        {
            PROOF_INSTS(int ghost_i = i;)
            buf[i++] = ure->attr[j]->flags;
            buf[i++] = ure->attr[j]->code;
            int add = 0;
            if (ure->attr[j]->code == AS_PATH) // gérer le cas où le length+4 dépasse la taille d'un byte
                add += 4;
            if (ure->attr[j]->flags & 0b00010000)
                buf[i++] = ebpf_ntohs((uint16_t)(ure->attr[j]->length + add));
            else
                buf[i] = (uint8_t) ure->attr[j]->length + add;
            i++;
            switch (ure->attr[j]->code) {
                case AS_PATH:
                    memcpy(buf+i, ure->attr[j]->data, 2);
                    i++;
                    buf[i]++;
                    i++;
                    uint32_t* bufs2 = (uint32_t*) (buf+i);
                    bufs2[0] = ebpf_htonl(peer->local_bgp_session->as);

                    i += 4;

                    NOT_T2(ebpf_memcpy(buf+i, ure->attr[j]->data+2, ure->attr[j]->length-2);)
                    PROOF_T2_INSTS(memcpy(buf+i, ure->attr[j]->data+2, ure->attr[j]->length-2);)
                    i += ure->attr[j]->length-2;
                    break;
		    
                case NEXT_HOP:
                    memcpy(buf + i, &(peer->nexthop.in), 4);
                    i += 4;
                    break;

                default:
                    NOT_T2(ebpf_memcpy(buf+i, ure->attr[j]->data, ure->attr[j]->length);)
                    PROOF_T2_INSTS(memcpy(buf+i, ure->attr[j]->data, ure->attr[j]->length);)
                    i += ure->attr[j]->length;
                    break;
                }
        }
        buf[i++] = (uint8_t) ure->pfx.prefixlen; //NLRI
        PROOF_T2_INSTS(
                memcpy(buf+i, ure->pfx.u, size_pfx(ure->pfx.prefixlen));
                i += 1; //prefixlen strictly > 1
        )
        NOT_T2(
                for (int k = 0 ; k < size_pfx(ure->pfx.prefixlen) PROOF_T2_INSTS(&& k < 4096); k++)
                    buf[i++] = ure->pfx.u[k];
        )

        log_prefix(ure->pfx.prefixlen, (uint8_t*)(buf+i-(size_pfx(ure->pfx.prefixlen))), UPDATE);
    }
    struct bgp_message msg = {.type = 2, .buf_len = i, .buf = buf};

    char* prefix_addr = ctx_calloc(52, 1);

    ebpf_inet_ntop((uint8_t*)&(peer->addr.addr), peer->addr.af, prefix_addr, 52);
    PROOF_SEAHORN_INSTS(struct bgp_message* p_msg = &msg);
    CHECK_UPDATE_MESSAGE(p_msg);
    CHECK_BUFFER(buf, msg.buf_len);
    schedule_bgp_message(2, &msg, prefix_addr);
    ctx_free(prefix_addr);
    return notEmpty;
}
