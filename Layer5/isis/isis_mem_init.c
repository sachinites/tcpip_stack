#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_lspdb.h"
#include "isis_pkt.h"
#include "isis_adjacency.h"
#include "isis_events.h"
#include "isis_flood.h"
#include "isis_intf_group.h"

void
 isis_mem_init() {

     MM_REG_STRUCT(0, isis_adj_state_t);
     MM_REG_STRUCT(0, isis_adjacency_t);
     MM_REG_STRUCT(0, isis_event_type_t);
     MM_REG_STRUCT(0, isis_lsp_pkt_t);
     MM_REG_STRUCT(0, isis_pkt_hdr_t);
     MM_REG_STRUCT(0, isis_timer_data_t);
     MM_REG_STRUCT(0, isis_reconc_data_t);
     MM_REG_STRUCT(0, isis_overload_data_t);
     MM_REG_STRUCT(0, isis_node_info_t);
     MM_REG_STRUCT(0, isis_intf_info_t);
     MM_REG_STRUCT(0, isis_lsp_xmit_elem_t);
     MM_REG_STRUCT(0, isis_intf_group_t);
     MM_REG_STRUCT(0, isis_adv_data_t);
 }
