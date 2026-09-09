#ifndef __DPCP_COMN__
#define __DPCP_COMN__

#include "libs/common/cmn_struct.h"

typedef struct dp_ctx_ dp_ctx_t;
struct rte_mbuf;
typedef struct pkt_q_ pkt_q_t;

void 
dp_punt_pkt_to_cp(dp_ctx_t *dp_ctx, struct rte_mbuf *mbuf);

void 
dp_pkt_q_enqueue (dp_ctx_t *dp_ctx, 
                  pkt_q_t *pkt_q, 
                  char *data, uint32_t data_size);


#pragma pack(push, 8)

typedef struct bd_lmac_data_ {

    uint32_t ip_addr;
    uint32_t ac_ifindex;
    uint32_t bd_ifindex;
    mac_addr_t mac;
    bool add;

} bd_lmac_data_t;

#pragma pack(pop)

#endif 