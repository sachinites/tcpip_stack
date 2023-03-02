#ifndef __ISIS_PKT_H__
#define __ISIS_PKT_H__
#include "../../tcp_public.h"
#include "isis_const.h"
#include <stdbool.h>
#include "isis_intf.h"

typedef struct isis_pkt_hdr_
{
    uint32_t isis_pkt_type;
    uint32_t seq_no;
    uint32_t rtr_id;
    uint32_t flags;
} isis_pkt_hdr_t;

bool isis_pkt_trap_rule(char *pkt, size_t pkt_size);

void isis_pkt_receive(void *arg, size_t *size);

byte *
isis_prepare_hello_pkt(interface_t *intf, size_t *hello_pkt_size);

#endif
