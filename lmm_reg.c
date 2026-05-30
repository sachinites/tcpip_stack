#include "tcp_public.h"
#include "libs/LinuxMemoryManager/mm.h"
#include "lmm_enums.h"

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

/* RTM files*/
#include "RTM/rtm_nb_integ.h"
#include "RTM/rtm_proto.h"
#include "RTM/rtm_nh.h"
#include "RTM/rtm_route.h"
#include "RTM/rtm_resolution.h"
#include "RTM/rtm_presentation.h"
#include "RTM/rtm.h"
#include "RTM/rtm_gc.h"

/* FIB Files*/
#include "datapath/FIB/fib.h"
#include "datapath/FIB/fib_nh.h"
#include "datapath/FIB/fib_route.h"


/* TED Hdr Files*/
#include "ted/ted.h"

/* Data path files */
#include "datapath/Layer2/arp/arp.h"
#include "datapath/Layer2/switching/mac_table.h"

/* Lib Hdr files */
#include "libs/mtrie/mtrie.h"
#include "libs/pkt-block/cp_pkt_block.h"
#include "libs/gluethread/glthread.h"

/* Notification files */
#include "Layer3/rt_notif.h"

/* LFA files */
#include "Layer3/LFA/cp/lfa.h"
#include "Layer3/LFA/cp/lfa_isis.h"

/* Layer 3 files */
#include "Layer3/layer3.h"

/* VXLAN files */
#include "Layer2/vxlan/cp/vxlan.h"
#include "datapath/Layer2/vxlan/vlan_vni_ht.h"

/* MPLS files */
#include "libs/common/mpls_lstack.h"

/* VRF files */
#include "vrf/vrf.h"


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

    /* Common Library Structures */
    MM_REG_STRUCT2(mtrie_t),
    MM_REG_STRUCT2(mtrie_node_t),
    MM_REG_STRUCT2(glthread_t),
    MM_REG_STRUCT2(glthread_data_node_t),


    /* RT Table Structures */
    MM_REG_STRUCT2(rt_route_flash_request_t),

    /* Pkt block */
    MM_REG_STRUCT2(cp_pkt_block_t),
    MM_REG_STRUCT2(pkt_mbuf_encap_meta_data_t),

    /* Layer2 Structures*/
    MM_REG_STRUCT2(arp_hdr_t),
    MM_REG_STRUCT2(ethernet_hdr_t),
    MM_REG_STRUCT2(arp_table_t),
    MM_REG_STRUCT2(arp_pending_entry_t),
    MM_REG_STRUCT2(arp_entry_t),
    MM_REG_STRUCT2(vlan_8021q_hdr_t),
    MM_REG_STRUCT2(vlan_ethernet_hdr_t),
    MM_REG_STRUCT2(mac_table_t),
    //MM_REG_STRUCT2(mac_table_entry_t),

    /* VXLAN Structures */
    MM_REG_STRUCT2(vxlan_vni_mapping_t),
    MM_REG_STRUCT2(vxlan_vni_db_t),
    MM_REG_STRUCT2(vlan_vni_ht_entry_t),
    MM_REG_STRUCT2(vni_vlan_ht_entry_t),
    MM_REG_STRUCT2(vlan_vni_ht_db_t),

    /* Layer3 Structures */
    MM_REG_STRUCT2(ip_hdr_t),
    //MM_REG_STRUCT2(nexthop_t),
    //MM_REG_STRUCT2(v6nexthop_t);
    MM_REG_STRUCT2(ipv6_addr_t),
    MM_REG_STRUCT2(ipv6_hdr_t),
    MM_REG_STRUCT2(srh_hdr_t),

    /* LFA Structures*/
    MM_REG_STRUCT2(lfa_t),

    /* RTM Structures*/
    MM_REG_STRUCT2(rtm_t),
    MM_REG_STRUCT2(cp_nexthop_template_t),
    MM_REG_STRUCT2(rtm_nh_proto_t),
    MM_REG_STRUCT2(rtm_proto_info_t),
    MM_REG_STRUCT2(rtm_nh),
    MM_REG_STRUCT2(rtm_route),
    MM_REG_STRUCT2(cmn_prefix_t),
    MM_REG_STRUCT2(rtm_rt_subscription_t),
    MM_REG_STRUCT2(rtm_gc_t),
    MM_REG_STRUCT2(rtm_presentation_data_t),
    //MM_REG_STRUCT2(rtm_ppt_route_t),
    MM_REG_STRUCT2(rtm_nh_fwd_info_t),

    /* MPLS files */
    MM_REG_STRUCT2(mpls_lstack_t),

    /* FIB Structures*/
    MM_REG_STRUCT2(fib_t),
    MM_REG_STRUCT2(fib_nh_t),
    MM_REG_STRUCT2(fib_route_t),
    //MM_REG_STRUCT2(fib_nh_fwd_info_t), // C++ Structure

    /* VRF Structures */
    MM_REG_STRUCT2(vrf_t),
    MM_REG_STRUCT2(def_vrf_t),

    {"nil", NULL,  {0, 0}, 0, 0, 0}
};

vm_page_family_t *
mm_get_page_family(uint32_t index) {

    return &vm_page_family_array[(struct_index_t)index];
}
