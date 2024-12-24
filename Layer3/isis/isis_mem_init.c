#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_intf.h"
#include "isis_lspdb.h"
#include "isis_pkt.h"
#include "isis_adjacency.h"
#include "isis_events.h"
#include "isis_flood.h"
#include "isis_intf_group.h"
#include "isis_spf.h"
#include "isis_policy.h"
#include "isis_advt.h"
#include "isis_struct.h"

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
     MM_REG_STRUCT(0, isis_spf_log_container_t);
     MM_REG_STRUCT(0, isis_spf_log_t);
     MM_REG_STRUCT(0, isis_spf_data_t);
     MM_REG_STRUCT(0, isis_spf_result_t);
     MM_REG_STRUCT(0, isis_fragment_t);
     MM_REG_STRUCT(0, isis_advt_db_t);
     MM_REG_STRUCT(0, isis_advt_info_t);
     MM_REG_STRUCT(0, isis_adv_data_t);
     MM_REG_STRUCT(0, isis_system_id_t);
     MM_REG_STRUCT(0, isis_lan_id_t);
     MM_REG_STRUCT(0, isis_lsp_id_t);
     MM_REG_STRUCT(0, isis_common_hdr_t);
     MM_REG_STRUCT(0, isis_p2p_hello_pkt_hdr_t);
     MM_REG_STRUCT(0, isis_lan_hello_pkt_hdr_t);
 }
