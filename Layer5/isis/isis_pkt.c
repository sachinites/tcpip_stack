#include "../../tcp_public.h"
#include "isis_pkt.h"
#include "isis_const.h"

bool
isis_pkt_trap_rule (char *pkt, size_t pkt_size) {

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)pkt;
    return (eth_hdr->type == ISIS_ETH_PKT_TYPE);
}

void
isis_pkt_receive(void *arg, size_t arg_size) {

    printf("%s() invoked\n", __FUNCTION__);
}