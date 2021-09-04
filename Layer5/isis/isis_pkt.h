#ifndef __ISIS_PKT__
#define __ISIS_PKT__

bool
isis_pkt_trap_rule (char *pkt, size_t pkt_size);

void
isis_pkt_receive(void *arg, size_t arg_size) ;

#endif 
