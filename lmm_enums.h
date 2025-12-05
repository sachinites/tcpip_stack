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
    MM_INDEX(mtrie_node_t),

    /* RT Table Structures */
    MM_INDEX(rt_route_flash_request_t),

    /* Pkt Block */
    MM_INDEX(pkt_block_t),
    MM_INDEX(encap_meta_data_t),

    /* Layer2 Structures */
    MM_INDEX(arp_hdr_t),
    MM_INDEX(ethernet_hdr_t),
    MM_INDEX(arp_table_t),
    MM_INDEX(arp_pending_entry_t),
    MM_INDEX(arp_entry_t),
    MM_INDEX(vlan_8021q_hdr_t),
    MM_INDEX(vlan_ethernet_hdr_t),
    MM_INDEX(mac_table_t),
    //MM_INDEX(mac_table_entry_t),

    /* VXLAN Structures */
    MM_INDEX(vxlan_vni_mapping_t),
    MM_INDEX(vxlan_vni_db_t),
    MM_INDEX(vlan_vni_ht_entry_t),
    MM_INDEX(vni_vlan_ht_entry_t),
    MM_INDEX(vlan_vni_ht_db_t),
    

    /* Layer3 Structures */
    MM_INDEX(ip_hdr_t),
    MM_INDEX(rt_table_t),
    //MM_INDEX(nexthop_t),
    MM_INDEX(l3_route_t),
    //MM_INDEX(v6nexthop_t),
    MM_INDEX(ipv6_route_t),
    MM_INDEX(ipv6_addr_t),
    MM_INDEX(ipv6_hdr_t),
    MM_INDEX(srh_hdr_t),

    /* LFA Structures*/
    MM_INDEX(lfa_t),

    /* RTM Structures*/
    MM_INDEX(rtm_t),
    MM_INDEX(cp_nexthop_template_t),
    MM_INDEX(rtm_nh_proto_t),
    MM_INDEX(rtm_proto_info_t),
    MM_INDEX(rtm_nh),
    MM_INDEX(rtm_route),
    MM_INDEX(rtm_prefix_t),
    MM_INDEX(rtm_lstack_t),
    MM_INDEX(rtm_rt_subscription_t),

    MM_INDEX(lstack_t)

    /* Add more Application structure Index here */

} struct_index_t;

#endif 