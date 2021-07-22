#ifndef __ISIS_STRUCT__
#define __ISIS_STRUCT__

#include "../../tcp_public.h"


typedef struct isis_node_info_ {

    char *local_lsp_pkt;
    size_t lsp_pkt_size;
} isis_node_info_t;

typedef struct isis_intf_info_ {

    uint16_t hello_interval;
    wheel_timer_elem_t *hello_xmit_timer;
} isis_intf_info_t;

#endif /* __ISIS_STRUCT__ */