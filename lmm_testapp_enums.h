#ifndef __LMM_ENUM__
#define __LMM_ENUM__

#define MM_INDEX(structname)  structname##_index

typedef enum struct_index_
{

    /* ISIS Structures */
    MM_INDEX(isis_adj_state_t),
    MM_INDEX(isis_adjacency_t),
    MM_INDEX(isis_event_type_t),
    MM_INDEX(isis_lsp_pkt_t),
    MM_INDEX(isis_pkt_hdr_t),
    MM_INDEX(isis_timer_data_t),
    MM_INDEX(isis_reconc_data_t),
    MM_INDEX(isis_overload_data_t),
    MM_INDEX(isis_node_info_t),
    MM_INDEX(isis_intf_info_t),
    MM_INDEX(isis_lsp_xmit_elem_t),
    MM_INDEX(isis_intf_group_t),
    MM_INDEX(isis_spf_log_container_t),
    MM_INDEX(isis_spf_log_t),
    MM_INDEX(isis_spf_data_t),
    MM_INDEX(isis_spf_result_t),
    MM_INDEX(isis_fragment_t),
    MM_INDEX(isis_advt_db_t),
    MM_INDEX(isis_advt_info_t),
    MM_INDEX(isis_adv_data_t),
    MM_INDEX(isis_system_id_t),
    MM_INDEX(isis_lan_id_t),
    MM_INDEX(isis_lsp_id_t),
    MM_INDEX(isis_common_hdr_t),
    MM_INDEX(isis_p2p_hello_pkt_hdr_t),
    MM_INDEX(isis_lan_hello_pkt_hdr_t),
    MM_INDEX(isis_srv6_locator_t),
    MM_INDEX(isis_srv6_pfx_sid_t),
    MM_INDEX(isis_srv6_adj_sid_t),
    MM_INDEX(isis_srv6_config_t),

    /* TED Structures */
    MM_INDEX(ted_intf_t),
    MM_INDEX(ted_node_t),
    MM_INDEX(ted_db_t),
    MM_INDEX(ted_link_t),
    MM_INDEX(ted_template_nbr_data_t),
    MM_INDEX(ted_template_node_data_t),
    MM_INDEX(ted_prefix_t),
    MM_INDEX(ted_v6prefix_t),

    /* Mtrie */
    MM_INDEX(mtrie_t),
    MM_INDEX(mtrie_node_t)


    /* Add more Application structure Index here */

} struct_index_t;

#endif 