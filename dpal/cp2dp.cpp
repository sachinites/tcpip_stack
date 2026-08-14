#include <assert.h>
#include <semaphore.h>

#include "../libs/common/cmn_prefix.h"
#include "../router_init.h"
#include "../libs/common/l3_hdrs.h"
#include "cp2dp.h"
#include "../libs/EventDispatcher/event_dispatcher.h"

#include "../libs/LinuxMemoryManager/uapi_mm.h"
#include "../Interface/InterfaceUApi.h"
#include "../libs/Tracer/tracer.h"
#include "../libs/common/ipv6_hdrs.h"
#include "../libs/pkt-block/pkt_mbuf.h"
#include "../libs/pkt-block/cp_pkt_block.h"
#include "../lmm_enums.h"
#include "../libs/LinuxMemoryManager/uapi_mm.h"
#include "../RTM/rtm_nb_integ.h"
#include "../RTM/rtm_nh.h"
#include "../Layer2/transport_svc.h"

/* Include DP interface files */
#include "../datapath/dp-program/dp-prog-struct.h"
#include "../datapath/dp-program/dp-prog-api.h"
#include "../datapath/dp_uapi.h"
#include "../datapath/dp_utils.h"
#include "../datapath/Layer3/ping.h"

/*  Fix me : cp2dp_xmit_pkt is allocated by CP but freed by DP. This is not a desirable thing to do.
    For now its not a problem, but in future when CP and DP will have separate memory mgr, 
    this would create problem.*/
void
cp2dp_xmit_pkt (node_t *node, cp_pkt_block_t *pkt_block, Interface *xmit_interface) {

    struct rte_mbuf *mbuf = cp2dp_convert_pkt_block (node->dp_ctx, pkt_block);
    dp_uapi_xmit_pkt(node->dp_ctx, xmit_interface->ifindex, mbuf);
    pkt_mbuf_dereference(mbuf);
}

void 
cp2dp_submit (node_t *node, dp_msg_t *dp_msg, bool async) {

    assert (dp_msg->data_size < sizeof(dp_msg->data));
    dp_uapi_submit_dp_msg(node->dp_ctx, dp_msg, async);
}


/* ================ cp2dp_Send APIs ==================== */


/* This is Control plane API to push IP data to be sent out from L4+ layer down to L3.
    pkt_block must contain IP payload . If there is no ip payload, then send NULL*/
void 
cp2dp_send_ip_data ( node_t *node,
                     vrf_t *vrf,
                     uint8_t *ip_payload,
                     pkt_size_t payload_size,
                     uint32_t dest_ip_addr,
                     uint16_t std_ip_protocol) {

    dp_raw_pkt_info_t *pkt_info;

    pkt_info = (dp_raw_pkt_info_t *)XCALLOC2(0, 1, dp_raw_pkt_info_t);
    pkt_info->pkt = (uint8_t *)XCALLOC_BUFF(0, sizeof(ip_hdr_t) + payload_size);
    pkt_info->pkt_size = sizeof(ip_hdr_t) + payload_size;
    pkt_info->lead_proto = IP_PROTO_IP_IN_IP;

    ip_hdr_t *ip_hdr = (ip_hdr_t *)pkt_info->pkt;
    pkt_size_t pkt_size = pkt_info->pkt_size;

    initialize_ip_hdr (ip_hdr);

    ip_hdr->protocol = (uint8_t)std_ip_protocol;
    ip_hdr->src_ip = htonl(tcp_ip_convert_ip_p_to_n(NODE_RTRID_ADDR(node)));
    ip_hdr->dst_ip = htonl(dest_ip_addr);
    ip_hdr->total_length = htons(pkt_size);

    if (ip_payload) {
        memcpy ((char *)ip_hdr + IP_HDR_LEN_IN_BYTES(ip_hdr) , ip_payload, payload_size);
    }

    dp_msg_t *dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = PKT_BLOCK;
    dp_msg->opr_type = DP_L3_NORTHBOUND_IN;
    dp_msg->vrf_id = vrf->vrf_id;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_raw_pkt_info_t);
    memcpy (dp_msg->data, &pkt_info, sizeof(dp_raw_pkt_info_t *));
    cp2dp_submit (node, dp_msg, true);
}

/* This is Control plane API to push IPv6 data to be sent out from L4+ layer down to L3.
    pkt_block must contain IPv6 payload . If there is no ipv6 payload, then send NULL*/
void 
cp2dp_send_ip6_data ( node_t *node,
                      vrf_t *vrf,
                      uint8_t *ipv6_payload,
                      pkt_size_t payload_size,
                      ipv6_addr_t dest_ip_addr,
                      uint16_t std_ip_protocol) {

    dp_raw_pkt_info_t *pkt_info;

    pkt_info = (dp_raw_pkt_info_t *)XCALLOC2(0, 1, dp_raw_pkt_info_t);
    pkt_info->pkt = (uint8_t *)XCALLOC_BUFF(0, sizeof(ipv6_hdr_t) + payload_size);
    pkt_info->pkt_size = sizeof(ipv6_hdr_t) + payload_size;
    pkt_info->lead_proto = IP_PROTO_IPv6;

    ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt_info->pkt;
    pkt_size_t pkt_size = pkt_info->pkt_size;

    initialize_ipv6_hdr (ipv6_hdr);

    ipv6_hdr->next_header = (uint8_t)std_ip_protocol;
    ipv6_hdr->payload_length = htons(pkt_size - sizeof(ipv6_hdr_t));
    memcpy (ipv6_hdr->dst_addr, dest_ip_addr.addr, 16);

    if (ipv6_payload) {
        memcpy ( ipv6_hdr + 1, ipv6_payload, payload_size);
    }

    dp_msg_t *dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = PKT_BLOCK;
    dp_msg->opr_type = DP_L3_NORTHBOUND_IN;
    dp_msg->vrf_id = vrf->vrf_id;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_raw_pkt_info_t);
    memcpy (dp_msg->data, &pkt_info, sizeof(dp_raw_pkt_info_t *));
    cp2dp_submit (node, dp_msg, true);
}
/* Wrapper fn to add MAC entry to MAC table Asynchronously*/
void
cp2dp_mac_table_entry_add (node_t *node,
                      uint8_t *mac_addr,
                      uint16_t vlan_id,
                      uint32_t ifindex,
                      uint16_t flags,
                      bool async,
                      uint32_t remote_dst_ip) {

    dp_msg_t *dp_msg;
    mac_update_msg_t *mac_update_msg;

    dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = MAC_TABLE;
    dp_msg->opr_type = DP_CREATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(mac_update_msg_t);
    mac_update_msg = (mac_update_msg_t *)dp_msg->data;
    
    memcpy(mac_update_msg->mac_addr, mac_addr, 6);
    mac_update_msg->vlan_id = vlan_id;
    mac_update_msg->ifindex = ifindex;
    mac_update_msg->flags = flags;
    mac_update_msg->remote_dst_ip = remote_dst_ip;
    
    cp2dp_submit(node, dp_msg, async);
}

void
cp2dp_mac_table_entry_del (node_t *node,
                      uint8_t *mac_addr,
                      uint16_t vlan_id,
                      uint32_t ifindex,
                      bool async,
                      uint32_t remote_dst_ip) {

    dp_msg_t *dp_msg;
    mac_update_msg_t *mac_update_msg;

    dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = MAC_TABLE;
    dp_msg->opr_type = DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(mac_update_msg_t);
    mac_update_msg = (mac_update_msg_t *)dp_msg->data;
    
    memcpy(mac_update_msg->mac_addr, mac_addr, 6);
    mac_update_msg->vlan_id = vlan_id;
    mac_update_msg->ifindex = ifindex;
    mac_update_msg->remote_dst_ip = remote_dst_ip;
    mac_update_msg->flags = 0; // Not needed for delete
    
    cp2dp_submit(node, dp_msg, async);
}

void
cp2dp_fib_update (
        node_t *node,
        uint8_t target_fib_vrf_id,
        AFI_T target_fib_afi,
        cmn_prefix_t *prefix,
        uint32_t nh_idx,
        uint32_t inh_idx,
        rtm_nh_fwd_info_t *fwd_info,
        FIB_OPN_T operation) {

    dp_msg_t *dp_msg = cp2dp_msg_alloc ();
    fib_update_msg_t *msg = (fib_update_msg_t *)dp_msg->data;

    /* Set message metadata */
    dp_msg->component_type = FIB_TABLE;
    dp_msg->opr_type = (operation == FIB_ADD) ? DP_CREATE : DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(fib_update_msg_t);
    dp_msg->vrf_id = target_fib_vrf_id;

    /* Populate FIB update message */
    msg->target_fib_vrf_id = target_fib_vrf_id;
    msg->target_fib_afi = target_fib_afi;
    msg->fwd_flags = fwd_info ? fwd_info->fwd_flags : 0;
    msg->nhidx = nh_idx;
    msg->inhidx = inh_idx;
    msg->prefix = *prefix;

    if (fwd_info){

         rtm_nh_fwd_info_t *src =  fwd_info;
         dp_fib_nh_fwd_info_t *dst = (dp_fib_nh_fwd_info_t *)&msg->fwd_info ;
 
         dst->oif = src->oif;
         dst->nh_addr = src->nh_addr;
         dst->fwd_flags = src->fwd_flags;

         if (src->fwd_flags & FIB_NH_FWD_F_MPLS_LBL_STCK) {
            memcpy (&dst->u.mpls_fwd.label_stack, 
                &src->u.mpls_fwd.label_stack, sizeof(dst->u.mpls_fwd.label_stack));
         }

         if (src->fwd_flags & FIB_NH_FWD_F_IPV6_STCK) {

            dst->u.v6_fwd.endfn = src->u.v6_fwd.endfn;
            dst->u.v6_fwd.n_segment_list = src->u.v6_fwd.n_segment_list;

            for (int i = 0; i < dst->u.v6_fwd.n_segment_list; i++) {
                memcpy(dst->u.v6_fwd.v6segment_lst[i],
                       src->u.v6_fwd.v6segment_lst[i],
                       sizeof(dst->u.v6_fwd.v6segment_lst[i]));
            }
         }

         if (src->fwd_flags & FIB_NH_FWD_F_TUNNEL)
         {
             dst->u.gre_fwd.gre_tunnel_src = src->u.gre_fwd.gre_tunnel_src;
             dst->u.gre_fwd.gre_tunnel_dst = src->u.gre_fwd.gre_tunnel_dst;
         }
    }

    /* Submit to data plane */
    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_vrf_create (node_t *node, char *vrf_name, uint8_t vrf_id) {

    dp_msg_t *dp_msg;
    dp_vrf_create_msg_t *vrf_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = VRF_TABLE;
    dp_msg->opr_type = DP_CREATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_vrf_create_msg_t);
    
    vrf_msg = (dp_vrf_create_msg_t *)dp_msg->data;
    vrf_msg->vrf_id = vrf_id;
    strncpy(vrf_msg->vrf_name, vrf_name, sizeof(vrf_msg->vrf_name) - 1);
    vrf_msg->vrf_name[sizeof(vrf_msg->vrf_name) - 1] = '\0';
    
    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_vrf_delete (node_t *node, uint8_t vrf_id) {

    dp_msg_t *dp_msg;
    dp_vrf_create_msg_t *vrf_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = VRF_TABLE;
    dp_msg->opr_type = DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_vrf_create_msg_t);
    
    vrf_msg = (dp_vrf_create_msg_t *)dp_msg->data;
    vrf_msg->vrf_id = vrf_id;
    vrf_msg->vrf_name[0] = '\0';
    
    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_vrf_delete_interface (node_t *node, uint8_t vrf_id, uint32_t ifindex) {

    dp_msg_t *dp_msg;
    dp_vrf_intf_update_msg_t *vrf_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = VRF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_vrf_intf_update_msg_t);
    
    /* Fill in the header */
    vrf_msg = (dp_vrf_intf_update_msg_t *)dp_msg->data;
    vrf_msg->op_code = DP_VRF_INTF_OP_DEL;
    vrf_msg->vrf_id = vrf_id;
    vrf_msg->ifindex = ifindex;
    
    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_vrf_add_interface (node_t *node, uint8_t vrf_id, uint32_t ifindex) {
    
    dp_msg_t *dp_msg;
    dp_vrf_intf_update_msg_t *vrf_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = VRF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_vrf_intf_update_msg_t);
    
    /* Fill in the header */
    vrf_msg = (dp_vrf_intf_update_msg_t *)dp_msg->data;
    vrf_msg->op_code = DP_VRF_INTF_OP_ADD;
    vrf_msg->vrf_id = vrf_id;
    vrf_msg->ifindex = ifindex;
    
    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_send_intf_ipv4_addr_update(node_t *node, 
                                uint32_t port_id, 
                                uint32_t ipv4_addr, 
                                uint8_t mask) {
    
    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;
    dp_intf_ipv4_addr_update_t *ipv4_update;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t) + sizeof(dp_intf_ipv4_addr_update_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = port_id;
    intf_msg->update_code = CP2DP_CODE_INTF_IPV4_ADDR;
    
    /* Fill in the IPv4 update data */
    ipv4_update = (dp_intf_ipv4_addr_update_t *)(intf_msg + 1);
    ipv4_update->ipv4_addr = ipv4_addr;
    ipv4_update->mask = mask;
    
    cp2dp_submit(node, dp_msg, true);
}

void
cp2dp_send_intf_gre_tunnel_update(node_t *node,
                                  uint32_t port_id,
                                  uint32_t lcl_ip,
                                  uint8_t mask,
                                  uint32_t tunnel_src_ip,
                                  uint32_t tunnel_dst_ip,
                                  bool tunnel_up) {

    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;
    dp_intf_gre_tunnel_update_t *gre_update;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t) +
                        sizeof(dp_intf_gre_tunnel_update_t);

    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = port_id;
    intf_msg->update_code = CP2DP_CODE_INTF_GRE_TUNNEL;

    gre_update = (dp_intf_gre_tunnel_update_t *)(intf_msg + 1);
    gre_update->lcl_ip = lcl_ip;
    gre_update->mask = mask;
    gre_update->tunnel_src_ip = tunnel_src_ip;
    gre_update->tunnel_dst_ip = tunnel_dst_ip;
    gre_update->tunnel_up = tunnel_up ? 1 : 0;

    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_send_intf_ipv6_addr_update(node_t *node, uint32_t port_id, uint8_t ipv6_addr[16], uint8_t prefix_len) {
    
    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;
    dp_intf_ipv6_addr_update_t *ipv6_update;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t) + sizeof(dp_intf_ipv6_addr_update_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = port_id;
    intf_msg->update_code = CP2DP_CODE_INTF_IPV6_ADDR;
    
    /* Fill in the IPv6 update data */
    ipv6_update = (dp_intf_ipv6_addr_update_t *)(intf_msg + 1);
    memcpy(ipv6_update->ipv6_addr, ipv6_addr, 16);
    ipv6_update->prefix_len = prefix_len;
    
    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_send_intf_vlan_bind_update(node_t *node, 
                                 uint32_t port_id, 
                                 uint32_t vlan_port_id, 
                                 IntfL2Mode l2_mode,
                                 bool add) {
    
    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;
    dp_intf_vlan_bind_t *vlan_bind;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t) + sizeof(dp_intf_vlan_bind_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = port_id;
    intf_msg->update_code = CP2DP_CODE_INTF_VLAN_BIND;
    
    /* Fill in the VLAN bind data */
    vlan_bind = (dp_intf_vlan_bind_t *)(intf_msg + 1);
    vlan_bind->port_id = port_id;
    vlan_bind->vlan_port_id = vlan_port_id;
    vlan_bind->l2_mode = (uint8_t)l2_mode;
    vlan_bind->add = (add) ? 1 : 0;
    
    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_send_intf_admin_status_update(node_t *node, uint32_t port_id, bool is_down) {
    
    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;
    dp_intf_admin_down_t *admin_down;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t) + sizeof(dp_intf_admin_down_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = port_id;
    intf_msg->update_code = CP2DP_CODE_INTF_ADMIN_DOWN;
    
    /* Fill in the admin status data */
    admin_down = (dp_intf_admin_down_t *)(intf_msg + 1);
    admin_down->port_id = port_id;
    admin_down->status = is_down;
    
    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_send_intf_vlan_vni_update(
        node_t *node, uint16_t vlan_port_id, 
        uint32_t vni_id, bool add) {

    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;
    dp_intf_vlan_vni_t *vni_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t) + sizeof(dp_intf_vlan_vni_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = (uint32_t)vlan_port_id;
    intf_msg->update_code = CP2DP_CODE_INTF_VLAN_VNI;
    
    /* Fill in the admin status data */
    vni_msg = (dp_intf_vlan_vni_t *)(intf_msg + 1);
    vni_msg->vni_id = vni_id;
    vni_msg->add = (add) ? 1 : 0;
    
    cp2dp_submit(node, dp_msg, true);    
}

void 
cp2dp_send_intf_switchport_update(node_t *node, uint32_t port_id, uint8_t switchport) {

    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;
    dp_intf_boolean_property_t *sw_status;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t) + sizeof(dp_intf_boolean_property_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = port_id;
    intf_msg->update_code = CP2DP_CODE_INTF_SW;
    
    /* Fill in the admin status data */
    sw_status = (dp_intf_boolean_property_t *)(intf_msg + 1);
    sw_status->port_id = port_id;
    sw_status->enable = switchport;
    
    cp2dp_submit(node, dp_msg, true);    
}

void 
cp2dp_send_intf_vlan_grp_bind_update(node_t *node, 
                    uint32_t port_id, 
                    bitmap_t *vlan_bitmap, 
                    bool add) {
    
    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;
    dp_intf_vlan_grp_bind_t *vlan_grp_bind;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t) + sizeof(dp_intf_vlan_grp_bind_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = port_id;
    intf_msg->update_code = CP2DP_CODE_INTF_VLAN_GRP_BIND;
    
    /* Fill in the VLAN group bind data */
    vlan_grp_bind = (dp_intf_vlan_grp_bind_t *)(intf_msg + 1);
    vlan_grp_bind->add = add ? 1 : 0;

    /* Copy the bitmap bits to the fixed-size array */
    size_t bitmap_bytes = (vlan_bitmap->tsize + 7) / 8; /* Number of bytes needed */

    if (bitmap_bytes > sizeof(vlan_grp_bind->vlan_bitmapp)) {
        bitmap_bytes = sizeof(vlan_grp_bind->vlan_bitmapp);
    }

    memcpy(vlan_grp_bind->vlan_bitmapp, vlan_bitmap->bits, bitmap_bytes);
    cp2dp_submit(node, dp_msg, true);
}


void 
cp2dp_interface_create (node_t *node, Interface *intf) {

    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;

    assert (intf->ifindex);

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_CREATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = intf->ifindex;
    intf_msg->vlan_id = (uint32_t)intf->GetVlanId();
    intf_msg->iftype = (uint32_t)intf->iftype;

    /* Some intf may not support MAC Addresses, for ex loopbacks*/
    if (intf->GetMacAddr()) {
        memcpy (intf_msg->mac_addr, intf->GetMacAddr()->mac, 6);
    }
    strncpy (intf_msg->intf_name, intf->if_name.c_str(), IF_NAME_SIZE);

    intf_msg->update_code = 0;

    switch (intf->iftype) {

        case INTF_TYPE_PHY:
        case INTF_TYPE_VLAN:
        case INTF_TYPE_GRE_TUNNEL:
        case INTF_TYPE_LOOPBACK:
        case INTF_TYPE_VIRTUAL_PORT:
            intf_msg->update_code = 0;
            break;
        case INTF_TYPE_RMAC:
            intf_msg->update_code = CP2DP_CODE_INTF_RMAC;
            break;
        case INTF_TYPE_VLAN_FLOOD:
            intf_msg->update_code = CP2DP_CODE_INTF_VLAN_FLOOD;
            break;
        case INTF_TYPE_NVE:
            intf_msg->update_code = CP2DP_CODE_INTF_NVE;
            break;
        case INTF_TYPE_HOST_PATH:
            intf_msg->update_code = CP2DP_CODE_INTF_HOST_PATH;
            break;
        case INTF_TYPE_UNKNOWN:
        default: 
            break;
    }

    /* Use synchronous submission to ensure interface is created before caller proceeds */
    cp2dp_submit(node, dp_msg, false);
}

void 
cp2dp_interface_delete (node_t *node, uint32_t ifindex) {

    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = ifindex;
    intf_msg->iftype = 0; // not required
    intf_msg->update_code = 0;
    
    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_interface_add_acl (node_t *node, 
                         uintptr_t acl,
                         uint8_t layer,
                         uint32_t ifindex, 
                         bool ingress) {

    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t) + 
                        sizeof(dp_intf_acl_update_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = ifindex;
    intf_msg->iftype = 0; // not required
    intf_msg->update_code = CP2DP_CODE_INTF_ADD_ACL;
    
    dp_intf_acl_update_t *acl_msg = (dp_intf_acl_update_t *)(intf_msg + 1);
    acl_msg->acl = acl;
    acl_msg->layer = layer;
    acl_msg->ingress = ingress;

    cp2dp_submit(node, dp_msg, true);    

}

void 
cp2dp_send_intf_grp_bind_to_vlan_update(node_t *node, 
                                        TransportService *tsp, 
                                        uint16_t vlan_id, bool add) {

    bool intf_fnd = false;
    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;
    dp_intf_grp_bind_t *bind_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_grp_bind_t);

    VlanInterface *vlan_intf = VlanInterface::VlanInterfaceLookUp(node, vlan_id);
    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = (uint32_t)vlan_intf->ifindex;
    intf_msg->iftype = (uint32_t)DP_INTF_TYPE_VLAN;
    intf_msg->vlan_id = (uint32_t)vlan_id;
    intf_msg->update_code = CP2DP_CODE_INTF_GRP_VLAN_BIND;

    dp_intf_grp_bind_t *msg = (dp_intf_grp_bind_t *)(intf_msg + 1);

    bitmap_t bm;
    bitmap_init(&bm, MAX_INTF_IFINDEX + 1);

    for (auto it2 = tsp->ifSet.begin(); it2 != tsp->ifSet.end(); ++it2)
    {
        uint16_t if_index = *it2;
        assert(if_index && if_index <= MAX_INTF_IFINDEX);
        bitmap_set_bit_at(&bm, if_index);
        intf_fnd = true;
    }

    if (!intf_fnd) {
        cp2dp_msg_free(dp_msg);
        bitmap_free_internal (&bm);
        return;
    }
    
    memcpy ((void *)msg->if_bitmapp, (void *)bm.bits, sizeof (msg->if_bitmapp));
    bitmap_free_internal (&bm);
    msg->add = add ? 1 : 0;

    cp2dp_submit(node, dp_msg, true);
}


void 
cp2dp_send_rmac(node_t *node, uint8_t (*mac)[6]) {

    dp_msg_t *dp_msg;
    dp_generic_msg_t *gen_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = DP_GENERICS;
    dp_msg->opr_type = DP_CREATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_generic_msg_t);
    
    /* Fill in the header */
    gen_msg = (dp_generic_msg_t *)dp_msg->data;
    gen_msg->opcode = DP_GENERIC_RMAC;
    memcpy (gen_msg->u.mac_addr, mac, 6);
    
    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_send_rtr_id(node_t *node, uint32_t rtr_id) {

    dp_msg_t *dp_msg;
    dp_generic_msg_t *gen_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = DP_GENERICS;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_generic_msg_t);
    
    /* Fill in the header */
    gen_msg = (dp_generic_msg_t *)dp_msg->data;
    gen_msg->opcode = DP_GENERIC_RTR_ID;
    gen_msg->u.rtr_id = rtr_id;
    
    cp2dp_submit(node, dp_msg, true);
}


void
cp2dp_srv6_dt4_intf_steered_vrf(node_t *node, 
                                Interface *intf, 
                                bool add) {

    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t);
    dp_msg->vrf_id = DEFAULT_VRF;

    SRv6EndPointEND_DT4_Egress_Interface *dt4_intf = 
        dynamic_cast<SRv6EndPointEND_DT4_Egress_Interface *>(intf);

    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = intf->ifindex;
    intf_msg->vlan_id = add ? dt4_intf->vrf->vrf_id : UINT32_MAX;
    intf_msg->iftype = (uint32_t)intf->iftype;
    intf_msg->update_code = CP2DP_CODE_DT4_INTF_STEER_VRF_BIND;

    cp2dp_submit(node, dp_msg, true);
}


void
cp2dp_send_switchport_intf_access (node_t *node, Interface *intf, bool add) {

    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;

    assert (intf->GetSwitchport());

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t);
    dp_msg->vrf_id = DEFAULT_VRF;

    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = intf->ifindex;
    intf_msg->iftype = (uint32_t)intf->iftype;
    intf_msg->update_code = CP2DP_CODE_INTF_ACCESS_MODE;

    dp_intf_boolean_property_t *bool_msg = (dp_intf_boolean_property_t *)(intf_msg +1);
    bool_msg->port_id = intf->ifindex;
    bool_msg->enable = add ? 1 : 0;

    cp2dp_submit(node, dp_msg, true);
}

void
cp2dp_send_vlan_add_access_port (node_t *node, 
                                    uint16_t vlan_id,
                                    uint32_t access_port_id, bool add) {

    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t);
    dp_msg->vrf_id = DEFAULT_VRF;

    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = access_port_id;
    intf_msg->vlan_id = vlan_id;
    intf_msg->iftype = 0;
    intf_msg->update_code = add ? 
        CP2DP_CODE_ACCESS_INTF_VLAN_ADD:                                                    
        CP2DP_CODE_ACCESS_INTF_VLAN_DEL;

    cp2dp_submit(node, dp_msg, true);
}

void
cp2dp_bd_ac_bind (node_t *node,
                  uint32_t bd_ifindex,
                  uint32_t ac_ifindex,
                  bool add) {

    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;
    dp_intf_bd_ac_bind_t *bind_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t) + sizeof(dp_intf_bd_ac_bind_t);

    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = ac_ifindex;
    intf_msg->iftype = 0;
    intf_msg->update_code = add ? CP2DP_CODE_BD_AC_BIND : CP2DP_CODE_BD_AC_UNBIND;

    bind_msg = (dp_intf_bd_ac_bind_t *)(intf_msg + 1);
    bind_msg->bd_port_id = bd_ifindex;
    bind_msg->ac_port_id = ac_ifindex;

    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_ping_request(node_t *node, 
                   ping_ctx_t *pctx) {

    dp_msg_t *dp_msg;
    dp_generic_msg_t *gen_msg;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = DP_GENERICS;
    dp_msg->opr_type = DP_CREATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_generic_msg_t);
    dp_msg->vrf_id = pctx->vrf_id;

    gen_msg = (dp_generic_msg_t *)dp_msg->data;
    gen_msg->opcode = DP_PING_REQ;
    gen_msg->u.ping.pctx = (uintptr_t)pctx;

    cp2dp_submit(node, dp_msg, true);
}

struct rte_mbuf *
cp2dp_convert_pkt_block (dp_ctx_t *dp_ctx, cp_pkt_block_t *cp_pkt_block) {

    struct rte_mbuf *mbuf =
        dp_pkt_mbuf_copy_and_wrap_raw_pkt_copy(
                dp_ctx, cp_pkt_block->pkt_start, cp_pkt_block->pkt_size);

    pkt_mbuf_update_new_hdr_type(mbuf, cp_pkt_block->hdr_type);
    return mbuf;
}

void
cp2dp_install_pkt_trap_rule (node_t *node,
                              uint32_t ifindex,
                              uint16_t id,
                              uint16_t l2_proto,
                              uint8_t ip_proto,
                              bool (*trap_fn)(struct rte_mbuf *),
                              void (*trap_app_cbk)(void *cp_ctx, struct rte_mbuf *),
                              event_dispatcher_t *ev_dis,
                              pkt_q_t *pkt_q,
                              bool consume) {

    dp_msg_t *dp_msg;
    dp_generic_msg_t *gen_msg;
    dp_pkt_trap_rule_t *trap_rule;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = DP_GENERICS;
    dp_msg->opr_type = DP_CREATE;
    dp_msg->flags = consume ? 1 : 0;
    dp_msg->data_size = sizeof(dp_generic_msg_t);

    gen_msg = (dp_generic_msg_t *)dp_msg->data;
    gen_msg->opcode = DP_TRAP_RULE;

    trap_rule = &gen_msg->u.trap_rule;
    trap_rule->ifindex = ifindex;
    trap_rule->id = id;
    trap_rule->proto = l2_proto ? l2_proto : (uint16_t)ip_proto;
    trap_rule->trap_examine_fn = (uintptr_t)trap_fn;
    trap_rule->trap_app_cbk = (uintptr_t)trap_app_cbk;
    trap_rule->ev_dis = (uintptr_t)ev_dis;
    trap_rule->pkt_q = (uintptr_t)pkt_q;

    cp2dp_submit(node, dp_msg, true);
}

void
cp2dp_uninstall_pkt_trap_rule (node_t *node,
                                uint32_t ifindex,
                                uint16_t id,
                                uint16_t l2_proto,
                                uint8_t ip_proto,
                                bool (*trap_fn)(struct rte_mbuf *),
                                void (*trap_app_cbk)(void *cp_ctx, struct rte_mbuf *),
                                event_dispatcher_t *ev_dis,
                                pkt_q_t *pkt_q,
                                bool consume) {

    dp_msg_t *dp_msg;
    dp_generic_msg_t *gen_msg;
    dp_pkt_trap_rule_t *trap_rule;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = DP_GENERICS;
    dp_msg->opr_type = DP_DEL;
    dp_msg->flags = consume ? 1 : 0;
    dp_msg->data_size = sizeof(dp_generic_msg_t);

    gen_msg = (dp_generic_msg_t *)dp_msg->data;
    gen_msg->opcode = DP_TRAP_RULE;

    trap_rule = &gen_msg->u.trap_rule;
    trap_rule->ifindex = ifindex;
    trap_rule->id = id;
    trap_rule->proto = l2_proto ? l2_proto : (uint16_t)ip_proto;
    trap_rule->trap_examine_fn = (uintptr_t)trap_fn;
    trap_rule->trap_app_cbk = (uintptr_t)trap_app_cbk;
    trap_rule->ev_dis = (uintptr_t)ev_dis;
    trap_rule->pkt_q = (uintptr_t)pkt_q;

    cp2dp_submit(node, dp_msg, true);
}

cp_pkt_block_t *
dp2cp_convert_pkt_block (struct rte_mbuf *mbuf) {

    pkt_size_t pkt_size = pkt_mbuf_get_data_size(mbuf);
    cp_pkt_block_t *cp_pkt_block = cp_pkt_block_get_new_pkt_buffer(pkt_size);
    uint8_t *pkt = pkt_mbuf_get_pkt(mbuf, NULL);
    memcpy(cp_pkt_block->pkt_start, pkt, pkt_size);
    cp_pkt_block->hdr_type = pkt_mbuf_get_starting_hdr(mbuf);
    return cp_pkt_block;
}