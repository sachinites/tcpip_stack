#include "../../tcp_public.h"
#include "isis_const.h"
#include "isis_pkt.h"
#include <stdbool.h>

bool 
isis_pkt_trap_rule(char* pkt, size_t pkt_size){

ethernet_hdr_t* header = (ethernet_hdr_t*)pkt;
return (header->type == ISIS_ETH_PKT_TYPE );

}

void 
isis_pkt_receive(void *arg, size_t *size){
 
}


