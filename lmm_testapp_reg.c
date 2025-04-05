#include "tcp_public.h"
#include "LinuxMemoryManager/mm.h"
#include "lmm_testapp_enums.h"

/* ISIS Hdr files */
#include "Layer3/isis/isis_enums.h"
#include "Layer3/isis/isis_rtr.h"
#include "Layer3/isis/isis_intf.h"
#include "Layer3/isis/isis_advt.h"
#include "Layer3/isis/isis_flood.h"
#include "Layer3/isis/isis_lspdb.h"
#include "Layer3/isis/isis_tlv_struct.h"
#include "Layer3/isis/isis_struct.h"
#include "Layer3/isis/isis_utils.h"
#include "Layer3/isis/isis_adjacency.h"
#include "Layer3/isis/isis_policy.h"
#include "Layer3/isis/isis_dis.h"
#include "Layer3/isis/isis_ted.h"
#include "Layer3/isis/isis_cmdcodes.h"
#include "Layer3/isis/isis_srv6.h"
#include "Layer3/isis/isis_spf.h"
#include "Layer3/isis/isis_intf_group.h"

/* TED Hdr Files*/
#include "ted/ted.h"

/* Lib Hdr files */
#include "mtrie/mtrie.h"

/* Create static array of vm_page_family_t */

#define MM_REG_STRUCT2(structname) \
    {#structname, NULL, {0,0}, structname##_index, sizeof(structname), 0, 0}

vm_page_family_t vm_page_family_array[] = 
{   
    /* ISIS Structures */
     MM_REG_STRUCT2(isis_adj_state_t),
     MM_REG_STRUCT2(isis_adjacency_t),
     MM_REG_STRUCT2(isis_event_type_t),
     MM_REG_STRUCT2(isis_lsp_pkt_t),
     MM_REG_STRUCT2(isis_pkt_hdr_t),
     MM_REG_STRUCT2(isis_timer_data_t),
     MM_REG_STRUCT2(isis_reconc_data_t),
     MM_REG_STRUCT2(isis_overload_data_t),
     MM_REG_STRUCT2(isis_node_info_t),
     MM_REG_STRUCT2(isis_intf_info_t),
     MM_REG_STRUCT2(isis_lsp_xmit_elem_t),
     MM_REG_STRUCT2(isis_intf_group_t),
     MM_REG_STRUCT2(isis_spf_log_container_t),
     MM_REG_STRUCT2(isis_spf_log_t),
     MM_REG_STRUCT2(isis_spf_data_t),
     MM_REG_STRUCT2(isis_spf_result_t),
     MM_REG_STRUCT2(isis_fragment_t),
     MM_REG_STRUCT2(isis_advt_db_t),
     MM_REG_STRUCT2(isis_advt_info_t),
     MM_REG_STRUCT2(isis_adv_data_t),
     MM_REG_STRUCT2(isis_system_id_t),
     MM_REG_STRUCT2(isis_lan_id_t),
     MM_REG_STRUCT2(isis_lsp_id_t),
     MM_REG_STRUCT2(isis_common_hdr_t),
     MM_REG_STRUCT2(isis_p2p_hello_pkt_hdr_t),
     MM_REG_STRUCT2(isis_lan_hello_pkt_hdr_t),
     MM_REG_STRUCT2(isis_srv6_locator_t),
     MM_REG_STRUCT2(isis_srv6_pfx_sid_t),
     MM_REG_STRUCT2(isis_srv6_adj_sid_t),
     MM_REG_STRUCT2(isis_srv6_config_t),   

    /* TED Structures */
    MM_REG_STRUCT2(ted_intf_t),
    MM_REG_STRUCT2(ted_node_t),
    MM_REG_STRUCT2(ted_db_t),
    MM_REG_STRUCT2(ted_link_t),
    MM_REG_STRUCT2(ted_template_nbr_data_t),
    MM_REG_STRUCT2(ted_template_node_data_t),
    MM_REG_STRUCT2(ted_prefix_t),
    MM_REG_STRUCT2(ted_v6prefix_t),

    /* Mtrie */
    MM_REG_STRUCT2(mtrie_t),
    MM_REG_STRUCT2(mtrie_node_t),

    {"nil", NULL,  {0, 0}, 0, 0, 0}
};

vm_page_family_t *
mm_get_page_family(uint32_t index) {

    return &vm_page_family_array[(struct_index_t)index];
}