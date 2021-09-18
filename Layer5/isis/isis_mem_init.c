#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_lspdb.h"
#include "isis_pkt.h"
#include "isis_adjacency.h"
#include "isis_events.h"
#include "isis_flood.h"

void
 isis_mem_init() {

     MM_REG_STRUCT(isis_adj_state_t);
     MM_REG_STRUCT(isis_adjacency_t);
     MM_REG_STRUCT(isis_event_type_t);
     MM_REG_STRUCT(isis_pkt_t);
     MM_REG_STRUCT(isis_pkt_hdr_t);
     MM_REG_STRUCT(isis_timer_data_t);
     MM_REG_STRUCT(isis_reconc_data_t);
     MM_REG_STRUCT(isis_overload_data_t);
     MM_REG_STRUCT(isis_node_info_t);
     MM_REG_STRUCT(isis_intf_info_t);
     MM_REG_STRUCT(isis_lsp_xmit_elem_t);
 }