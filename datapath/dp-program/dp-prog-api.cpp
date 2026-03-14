#include <stdlib.h>
#include <arpa/inet.h>

/* Libs */
#include "../../pkt_block.h"
#include "../../Tracer/tracer.h"
#include "../../LinuxMemoryManager/uapi_mm.h"

#include "../enums/l3_enums.h"
#include "dp-prog-struct.h"
#include "dp-prog-api.h"

#include "../dp_ctx.h"
#include "../Layer3/layer3.h"

#include "../Layer2/switching/mac_table.h"
#include "../Layer2/vxlan/vlan_vni_ht.h"


#include "../Vrfs/dp_vrf.h"

#include "../Interface/dp_intf.h"
#include "../Interface/dp_intf_store.h"

/* Fibs */
#include "../FIB/fib_error.h"
#include "../FIB/fib_nh.h"
#include "../FIB/fib.h"
#include "../FIB/fib_route.h"

extern void
dp_uapi_trace_dp_msg ( dp_ctx_t *dp_ctx, dp_msg_t *dp_msg);

static inline bool 
dp_bitmap_at(uint8_t *bit_array, uint16_t index) {

    uint16_t n_blocks = index / 32;
    uint8_t bit_pos = index % 32;
    uint32_t *ptr = (uint32_t *)(bit_array) + n_blocks;
    return htonl(*ptr) & (1 << (32 - bit_pos - 1));  
}

dp_msg_t *
cp2dp_msg_alloc()
{
    dp_msg_t *dp_msg = (dp_msg_t *)calloc(1, sizeof(dp_msg_t));
    dp_msg->vrf_id = DP_DEFAULT_VRF;
    return dp_msg;
}

void
cp2dp_msg_free (dp_msg_t *dp_msg){
    
    free (dp_msg);
}

/* Mac Table Updates*/
void
dp_mac_table_process_msg(dp_ctx_t *dp_ctx, dp_msg_t *dp_msg)  {
    
    mac_update_msg_t *mac_update_msg;
    mac_table_t *mac_table = dp_ctx->mac_table;
    
    assert(dp_msg->component_type == MAC_TABLE);
    
    switch (dp_msg->opr_type) {
        
        case DP_CREATE:
            mac_update_msg = (mac_update_msg_t *)dp_msg->data;
            mac_table_entry_add (dp_ctx, mac_table, 
                                                    mac_update_msg->mac_addr,   
                                                    mac_update_msg->vlan_id,
                                                    mac_update_msg->ifindex,
                                                    mac_update_msg->flags,
                                                    mac_update_msg->remote_dst_ip);
            break;
            
        case DP_DEL:
            mac_update_msg = (mac_update_msg_t *)dp_msg->data;
            mac_table_entry_delete (dp_ctx, mac_table, 
                                                    mac_update_msg->mac_addr,   
                                                    mac_update_msg->vlan_id,
                                                    mac_update_msg->ifindex,
                                                    mac_update_msg->remote_dst_ip);
            break;
            
        case DP_UPDATE:
            // Handle MAC entry updates if needed
            break;
            
        case DP_READ:
            // Handle MAC table reads if needed
            break;
            
        default:
            break;
    }
    
    cp2dp_msg_free(dp_msg);
}

void
np_recv_cp_pkt_block(dp_ctx_t *dp_ctx, dp_msg_t *dp_msg)
{
    pkt_block_t *pkt_block;
    hdr_type_t hdr_type;
    uint8_t vrf_id = dp_msg->vrf_id;

    dp_vrf_t *vrf = dp_look_up_vrf(dp_ctx->dp_vrf_ht, vrf_id);

    pkt_block = *(pkt_block_t **)dp_msg->data;

    switch (dp_msg->opr_type)
    {
        case DP_L3_NORTHBOUND_IN:
        {
            hdr_type = pkt_block_get_starting_hdr(pkt_block);

            switch (hdr_type)
            {
            case IP_HDR:
                dp_send_ip_data(dp_ctx, vrf, pkt_block);
                break;
            case IP6_HDR:
                dp_send_ip6_data(dp_ctx, vrf, pkt_block);
                break;
            default:
                break;
            }
        }
    break;

    default:
        break;
    }

    pkt_block_dereference(pkt_block);
    cp2dp_msg_free(dp_msg);
}

void
dp_fib_table_process_msg(dp_ctx_t *dp_ctx, dp_msg_t *dp_msg) {
    
    char nh_str[48];
    char route_str[48];
    fib_error_t rc;
    fib_t *fib = NULL;
    fib_nh_t *nh = NULL;
    fib_update_msg_t *fib_update_msg;

    assert(dp_msg->component_type == FIB_TABLE);

    fib_update_msg = (fib_update_msg_t *)dp_msg->data;

    tracer (dp_ctx->dptr, DFIB, 
        "FIB : Recvd fib update message : Route:%s vrf:%d idx[%u %u] ops:%d\n", 
            cmn_prefix_to_string(&fib_update_msg->prefix, &route_str), 
            fib_update_msg->target_fib_vrf_id,
            fib_update_msg->inhidx >> 31, 
            fib_update_msg->nhidx & 0x00000000FFFFFFFF, 
            dp_msg->opr_type);

    switch (dp_msg->opr_type) {
        
        case DP_CREATE:
        {
            fib = fib_get (dp_ctx, 
                    (AFI_T)fib_update_msg->target_fib_afi,
                     fib_update_msg->target_fib_vrf_id);
        
            if (!fib) {
                tracer (dp_ctx->dptr, DFIB | DERR, 
                       "FIB : FIB not initialized for AFI:%d VRF:%d\n",
                       fib_update_msg->target_fib_afi, 
                       fib_update_msg->target_fib_vrf_id);
                cp2dp_msg_free(dp_msg);
                return;
            }
            
            /* Create nexthop from forwarding info */
            fib_nh_t nh_template;
            memset (&nh_template, 0, sizeof(fib_nh_t));
            avltree_node_init (&nh_template.idx_glue);

            nh_template.fwd_info = 
                (fib_nh_fwd_info_t *)calloc(1, sizeof(fib_nh_fwd_info_t));

            rtm_fib_copy_fwd_info (dp_ctx, 
                &fib_update_msg->fwd_info, nh_template.fwd_info);
            
            nh = fib_nh_lookup(fib, &nh_template);

            if (!nh) {

                nh = fib_nh_create(fib, &nh_template);
           
                if (!nh) {
                    tracer (dp_ctx->dptr, DFIB | DERR, 
                        "FIB[%s] : Error : Route %s : Failed to create nexthop %s\n", 
                        fib->name,
                        route_str,
                        cmn_prefix_to_string(&nh_template.fwd_info->nh_addr, &nh_str));
                    free (nh_template.fwd_info);
                    cp2dp_msg_free(dp_msg);
                    return;
                }
                tracer (dp_ctx->dptr, DFIB_DET, 
                    "FIB[%s] : Route %s : New nexthop %s Created and Registered\n", 
                    fib->name,
                    route_str,
                    cmn_prefix_to_string(&nh_template.fwd_info->nh_addr, &nh_str));
                fib_register_nh(fib, nh);
            }
            else {
                tracer (dp_ctx->dptr, DFIB_DET, 
                    "FIB[%s] : Route %s : Existing nexthop %s Reused\n", 
                    fib->name, route_str,
                    cmn_prefix_to_string(&nh_template.fwd_info->nh_addr, &nh_str));
            }

            free(nh_template.fwd_info);

            rc = fib_add_route(dp_ctx,
                    fib, 
                    &fib_update_msg->prefix, 
                    fib_update_msg->inhidx,
                    fib_update_msg->nhidx, nh);
            
            if (rc != FIB_ERROR_SUCCESS) {
                tracer (dp_ctx->dptr, DFIB | DERR, 
                       "FIB[%s] : Failed to add route %s, error: %s\n",
                       fib->name, route_str, fib_error_str(rc));
                free( nh->fwd_info);
                XFREE(nh);
            }
            break;
        }
            
        case DP_DEL:
        {   
            fib = fib_get (dp_ctx, 
                    (AFI_T)fib_update_msg->target_fib_afi,
                     fib_update_msg->target_fib_vrf_id);

            if (!fib) {
                tracer (dp_ctx->dptr, DFIB | DERR, 
                       "FIB : FIB not initialized for AFI:%d VRF:%d\n",
                       fib_update_msg->target_fib_afi, 
                       fib_update_msg->target_fib_vrf_id);
                cp2dp_msg_free(dp_msg);
                return;
            }
            
            rc = fib_del_route(dp_ctx, fib, 
                    &fib_update_msg->prefix, 
                    fib_update_msg->inhidx,
                    fib_update_msg->nhidx);
            
            if (rc != FIB_ERROR_SUCCESS) {
                tracer (dp_ctx->dptr, DFIB | DERR, 
                       "FIB[%s] : Failed to delete route, error: %s\n",
                       fib->name, fib_error_str(rc));
            }
            break;
        }
            
        case DP_UPDATE:
            // Handle FIB entry updates if needed
            break;
            
        case DP_READ:
            // Handle FIB reads if needed
            break;
            
        default:
            break;
    }
    
    cp2dp_msg_free(dp_msg);
}

void
dp_vrf_table_process_msg(dp_ctx_t *dp_ctx, dp_msg_t *dp_msg) {

    assert(dp_msg->component_type == VRF_TABLE);

    switch (dp_msg->opr_type) {
        
        case DP_CREATE:
        {
            dp_vrf_create_msg_t *vrf_msg = (dp_vrf_create_msg_t *)dp_msg->data;
            dp_vrf_t *vrf = dp_create_vrf(dp_ctx->dp_vrf_ht, vrf_msg->vrf_name, vrf_msg->vrf_id);
            if (vrf_msg->vrf_id == DEFAULT_VRF) dp_ctx->default_vrf = vrf;
            break;
        }
        
        case DP_DEL:
        {
            dp_vrf_create_msg_t *vrf_msg = (dp_vrf_create_msg_t *)dp_msg->data;
            dp_delete_vrf(dp_ctx, dp_ctx->dp_vrf_ht, vrf_msg->vrf_id);
            if (vrf_msg->vrf_id == DEFAULT_VRF) dp_ctx->default_vrf = NULL;
            break;
        }
        
        case DP_UPDATE:
        {
            dp_vrf_intf_update_msg_t *msg = (dp_vrf_intf_update_msg_t *)dp_msg->data;
            switch (msg->op_code) {

                case DP_VRF_INTF_OP_ADD:
                {
                    dp_vrf_t *vrf = dp_look_up_vrf(dp_ctx->dp_vrf_ht, msg->vrf_id);
                    dp_intf_t *intf = dp_look_up_interface(dp_ctx->dp_intf_ht, msg->ifindex);
                    assert (intf && vrf);
                    assert (!intf->vrf);
                    intf->vrf = vrf;
                    tracer (dp_ctx->dptr, DCONF, 
                        "Interface if_name=%s bound to VRF %s, %p\n", intf->if_name, vrf->vrf_name, intf);
                }
                break;
                case DP_VRF_INTF_OP_DEL:
                {
                    dp_vrf_t *vrf = dp_look_up_vrf(dp_ctx->dp_vrf_ht, msg->vrf_id);
                    dp_intf_t *intf = dp_look_up_interface(dp_ctx->dp_intf_ht, msg->ifindex);
                    assert(intf && vrf);
                    assert(intf->vrf && (intf->vrf == vrf));
                    intf->vrf = NULL;
                    tracer (dp_ctx->dptr, DCONF, 
                        "Interface if_name=%s Unbound from VRF %s\n", intf->if_name, vrf->vrf_name);                    
                }   
                break;
            }
        }
        break;
        case DP_READ:
        default:
            break;
    }
    
    cp2dp_msg_free(dp_msg);
}


void 
dp_intf_table_process_msg(dp_ctx_t *dp_ctx, dp_msg_t *dp_msg){

    dp_intf_t *intf = NULL;
    char ip_str[INET_ADDRSTRLEN];
    char ipv6_str[INET6_ADDRSTRLEN];
    hashtable_t *ht = dp_ctx->dp_intf_ht;

    assert (dp_msg->component_type == INTF_TABLE);

    switch (dp_msg->opr_type) {

        case DP_CREATE:
        {
            dp_intf_cp2dp_msg_hdr_t *msg = 
                (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;

            tracer(dp_ctx->dptr, DCONF, 
                "Creating interface if_name=%s iftype=%u\n",
                msg->intf_name, msg->iftype);

            intf = dp_look_up_interface(ht, msg->port_id);
            assert (!intf);
            intf = dp_create_interface(msg->port_id, msg->iftype, 
                        &msg->mac_addr, (uint16_t)msg->vlan_id);
            strncpy(intf->if_name, msg->intf_name, sizeof (msg->intf_name));

            switch (msg->update_code) {

                case CP2DP_CODE_INTF_PHYSICAL:

                    dp_insert_interface(ht, intf);

                    if (intf->if_type == DP_INTF_TYPE_VLAN) {
                        dp_insert_vlan_interface (dp_ctx->dp_vlan_intf_ht, intf);
                    }
                    
                    else if (intf->if_type == DP_INTF_TYPE_PHY)
                    {
                        /* Initialize log file */
                        char intf_log_file_name[128];
                        snprintf(intf_log_file_name, sizeof(intf_log_file_name),
                                 "logs/%s-%s.txt",
                                 dp_ctx->ctx_name, intf->if_name);

                        intf->log_info.log_file = fopen(intf_log_file_name, "w");
                    }
                    break;
                case CP2DP_CODE_INTF_RMAC:
                    dp_ctx->dp_rmac_intf = intf;
                    break;
                case CP2DP_CODE_INTF_VLAN_FLOOD:
                    dp_ctx->dp_vlan_flood_intf = intf;
                    break;
                case CP2DP_CODE_INTF_NVE:
                    dp_ctx->dp_nve_intf = intf;
                    break;
                case CP2DP_CODE_INTF_HOST_PATH:
                    dp_ctx->dp_host_path_intf = intf;
                    break;
                default: 
                    dp_insert_interface(ht, intf);
                    break;
            }
            
            tracer(dp_ctx->dptr, DCONF, 
                "Interface if_name=%s created successfully\n",
                intf->if_name);
        }   
        break;

        case DP_DEL:
        {
            dp_intf_cp2dp_msg_hdr_t *msg = 
                (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
            char if_name_saved[IF_NAME_SIZE] = {0};
            
            intf = dp_look_up_interface(ht, msg->port_id);

            if (intf) {

                if (intf->if_type == DP_INTF_TYPE_VLAN) {
                    dp_remove_vlan_interface(dp_ctx->dp_vlan_intf_ht, intf->vlan_id);
                }

                dp_delete_interface(ht, msg->port_id);

                tracer(dp_ctx->dptr, DCONF, 
                    "Interface if_name=%u deleted\n", msg->port_id);
                break;
            }

            /* Check if this is special interface*/
            if (msg->port_id == dp_ctx->dp_rmac_intf->port_id) {
                dp_check_and_free_interface(dp_ctx->dp_rmac_intf);
                dp_ctx->dp_rmac_intf = NULL;
            }
            else if (msg->port_id == dp_ctx->dp_vlan_flood_intf->port_id) {
                dp_check_and_free_interface(dp_ctx->dp_vlan_flood_intf);
                dp_ctx->dp_vlan_flood_intf = NULL;
            }
            else if (msg->port_id == dp_ctx->dp_host_path_intf->port_id) {
                dp_check_and_free_interface(dp_ctx->dp_host_path_intf);
                dp_ctx->dp_host_path_intf = NULL;
            }
            else if (msg->port_id == dp_ctx->dp_nve_intf->port_id) {
                dp_check_and_free_interface(dp_ctx->dp_nve_intf);
                dp_ctx->dp_nve_intf = NULL;
            }         
            else {
                tracer(dp_ctx->dptr, DCONF|DERR, 
                    "Interface port_id=%u not found\n", msg->port_id);
                break;
            }                           
            
            tracer(dp_ctx->dptr, DCONF, 
                "Interface port_id=%u deleted\n", msg->port_id);
        }
        break;

        case DP_UPDATE:
        {
            dp_intf_cp2dp_msg_hdr_t *msg = 
                (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;

            intf = dp_look_up_interface(ht, msg->port_id);
            assert (intf);

            /* Process update based on update_code */
            switch (msg->update_code) {

                case CP2DP_CODE_INTF_IPV4_ADDR:
                {
                    dp_intf_ipv4_addr_update_t *ipv4_update = 
                        (dp_intf_ipv4_addr_update_t *)(msg + 1);
                    
                    tcp_ip_covert_ip_n_to_p(ipv4_update->ipv4_addr, (c_string)ip_str);
                    
                    tracer(dp_ctx->dptr, DCONF, 
                        "Updating IPv4 address on if_name=%s to %s/%u\n",
                        intf->if_name, ip_str, ipv4_update->mask);
                    
                    intf->ip_addr = ipv4_update->ipv4_addr;
                    intf->mask = ipv4_update->mask;
                }
                break;

                case CP2DP_CODE_INTF_IPV6_ADDR:
                {
                    dp_intf_ipv6_addr_update_t *ipv6_update = 
                        (dp_intf_ipv6_addr_update_t *)(msg + 1);
                    
                    inet_ntop(AF_INET6, ipv6_update->ipv6_addr, ipv6_str, sizeof(ipv6_str));
                    
                    tracer(dp_ctx->dptr, DCONF, 
                        "Updating IPv6 address on if_name=%s to %s/%u\n",
                        intf->if_name, ipv6_str, ipv6_update->prefix_len);
                    
                    memcpy(intf->v6addr, ipv6_update->ipv6_addr, 16);
                    intf->v6mask = ipv6_update->prefix_len;
                }
                break;

                case CP2DP_CODE_INTF_VLAN_BIND:
                {
                    dp_intf_vlan_bind_t *vlan_bind = 
                        (dp_intf_vlan_bind_t *)(msg + 1);

                    /* Look up the VLAN interface */
                    dp_intf_t *vlan_intf = dp_look_up_interface(ht, vlan_bind->vlan_port_id);
                
                    if (vlan_bind->add) {
                        dp_vlan_bind_port (vlan_intf, intf, (DP_IntfL2Mode)vlan_bind->l2_mode);
                    }
                    else {
                        dp_vlan_unbind_port (vlan_intf, intf, (DP_IntfL2Mode)vlan_bind->l2_mode, true);
                    }
                    tracer(dp_ctx->dptr, DCONF, 
                        "%sBinding %s with %s l2_mode=%s\n",
                        vlan_bind->add ? "" : "Un",
                        vlan_intf->if_name, intf->if_name,
                        dp_intf_mode_str((DP_IntfL2Mode)vlan_bind->l2_mode));
                }
                break;

                case CP2DP_CODE_INTF_ADMIN_DOWN:
                {
                    dp_intf_admin_down_t *admin_down = 
                        (dp_intf_admin_down_t *)(msg + 1);
                    
                    tracer(dp_ctx->dptr, DCONF, 
                        "Setting admin status on if_name=%s to %s\n",
                        intf->if_name, admin_down->status ? "DOWN" : "UP");
                    
                    intf->is_up = !admin_down->status;  /* status true means down, so invert */
                }
                break;

                case CP2DP_CODE_INTF_SW:
                {
                    dp_intf_switchpor_t *sw_status = 
                        (dp_intf_switchpor_t *)(msg+1);
                    tracer(dp_ctx->dptr, DCONF, 
                        "Setting switchport on if_name=%s to %d\n",
                        intf->if_name, sw_status->enable ? 1 : 0);
                    intf->switchport = sw_status->enable;
                }
                break;

                case CP2DP_CODE_INTF_VLAN_VNI:
                {
                    dp_intf_vlan_vni_t *vni_msg = 
                        (dp_intf_vlan_vni_t *)(msg + 1);
                    
                    if (vni_msg->add){
                        assert(!intf->vni_id);
                        intf->vni_id = vni_msg->vni_id;
                        vlan_vni_ht_add_mapping(dp_ctx,
                                                intf->vlan_id, intf->vni_id);
                    }
                    else {
                        assert (intf->vni_id == vni_msg->vni_id);
                        intf->vni_id = 0;
                        vlan_vni_ht_remove_mapping(dp_ctx, intf->vni_id);
                    } 
                }
                break;

                /* When TSP is attached/detached from an ethernet interface*/
                case CP2DP_CODE_INTF_VLAN_GRP_BIND:
                {
                    dp_intf_vlan_grp_bind_t *vlan_grp_bind =
                        (dp_intf_vlan_grp_bind_t *)(msg + 1);

                    dp_intf_t *vlan_intf;

                    struct hashtable_itr *itr = hashtable_iterator(ht);
                    while (1)
                    {
                        vlan_intf = (dp_intf_t *)hashtable_iterator_value(itr);

                        if (vlan_intf->if_type != DP_INTF_TYPE_VLAN) {
                            if (hashtable_iterator_advance(itr)) continue; break;
                        }

                        if (!dp_bitmap_at(vlan_grp_bind->vlan_bitmapp, vlan_intf->vlan_id)) {
                            if (hashtable_iterator_advance(itr)) continue; break;   
                        }

                        if (vlan_grp_bind->add) {
                            dp_vlan_bind_port(vlan_intf, intf, DP_LAN_TRUNK_MODE);
                        }
                        else {
                            dp_vlan_unbind_port(vlan_intf, intf, DP_LAN_TRUNK_MODE, false);
                        }

                        if (!hashtable_iterator_advance(itr)) break;
                    }
                    free(itr);

                    if (!vlan_grp_bind->add) {
                     intf->l2_mode = DP_LAN_MODE_NONE;   
                    }

                    tracer(dp_ctx->dptr, DCONF,
                           "DP INTF: Interface if_name=%s %sbound %s VLAN group\n",
                           intf->if_name, vlan_grp_bind->add ? "" : "Un",
                           vlan_grp_bind->add ? "to" : "from");
                }
                break;


                /* When vlan is added/deleted to existing TSP*/
                case CP2DP_CODE_INTF_GRP_VLAN_BIND:
                {
                    dp_intf_grp_bind_t *intf_grp_bind = 
                        (dp_intf_grp_bind_t *)(msg + 1);
                    
                    dp_intf_t *vlan_intf = intf;
                    dp_intf_t *member_intf;
                    uint32_t count = 0;

                    struct hashtable_itr *itr = hashtable_iterator(ht);
                    while (1) {
                        member_intf = (dp_intf_t *)hashtable_iterator_value(itr);

                        /* Filter interfaces which cannot be member ports of a vlan*/
                        if (member_intf->if_type == DP_INTF_TYPE_VLAN       || 
                            member_intf->if_type == DP_INTF_TYPE_GRE_TUNNEL ||
                            member_intf->if_type == DP_INTF_TYPE_LOOPBACK   ||
                            member_intf->if_type == DP_INTF_TYPE_NVE) {

                            if (hashtable_iterator_advance(itr)) continue; break;   
                        }

                        if (!dp_bitmap_at(intf_grp_bind->if_bitmapp, member_intf->port_id)) {
                            if (hashtable_iterator_advance(itr)) continue; break;    
                        }

                        if (intf_grp_bind->add)
                            dp_vlan_bind_port(vlan_intf, member_intf, DP_LAN_TRUNK_MODE);
                        else 
                            dp_vlan_unbind_port(vlan_intf, member_intf, DP_LAN_TRUNK_MODE, true);

                        count++;

                        if (!hashtable_iterator_advance(itr)) break;
                    }
                    free(itr);

                    tracer(dp_ctx->dptr, DCONF, 
                        ("DP INTF : %u member ports successfully %s %s %s\n", 
                            count, intf_grp_bind->add ? "Added" : "Removed",
                            intf_grp_bind->add ? "to" : "from",
                            vlan_intf->if_name));
                }
                break;


                case CP2DP_CODE_DT4_INTF_STEER_VRF_BIND:

                    if (msg->vlan_id != UINT32_MAX) {

                        assert(!intf->srv6_data.steered_dt4_vrf);
                        dp_vrf_t *steered_vrf = dp_look_up_vrf(dp_ctx->dp_vrf_ht, (uint16_t) msg->vlan_id);
                        assert(steered_vrf);
                        intf->srv6_data.steered_dt4_vrf = steered_vrf;
                    }
                    else {
                        assert(intf->srv6_data.steered_dt4_vrf);
                        intf->srv6_data.steered_dt4_vrf = NULL;
                    }

                break;



                default:
                    tracer(dp_ctx->dptr, DCONF, 
                        "Unknown update code %u for if_name=%s\n",
                        msg->update_code, intf->if_name);
                    break;
            }
        }
        break;

        case DP_READ:
            tracer(dp_ctx->dptr, DCONF, "Read operation (not implemented)\n");
            break;

        case DP_L3_NORTHBOUND_IN:
            tracer(dp_ctx->dptr, DCONF, "L3 northbound operation (not applicable)\n");
            break;

        default:
            tracer(dp_ctx->dptr, DCONF, "Unknown operation type %d\n", dp_msg->opr_type);
            break;
    }

EXIT:
    cp2dp_msg_free(dp_msg);
}

void 
dp_generic_process_msg(dp_ctx_t *dp_ctx, dp_msg_t *dp_msg) {

    dp_generic_msg_t *gen_msg;
    
    assert(dp_msg->component_type == DP_GENERICS);

    gen_msg = (dp_generic_msg_t *)dp_msg->data;

    switch (dp_msg->opr_type)
    {
        case DP_CREATE:

            switch (gen_msg->opcode)
            {
                case DP_GENERIC_RMAC:
                memcpy(&dp_ctx->rmac.mac, &gen_msg->u.mac_addr, 6);
                break;
            }
            break;

        case DP_UPDATE:
            switch (gen_msg->opcode)
            {
                case DP_GENERIC_RMAC:
                memcpy(&dp_ctx->rmac.mac, &gen_msg->u.mac_addr, 6);
                break;
            }
            break;

        case DP_DEL:
            switch (gen_msg->opcode)
            {
                case DP_GENERIC_RMAC:
                memset(&dp_ctx->rmac.mac, 0, 6);
                break;
            }
            break;
    }

    cp2dp_msg_free(dp_msg);
}

void 
cp2dp_task_handler  (event_dispatcher_t *ev_dis,  void *arg, uint32_t arg_size) {

    // This function is the task handler for the task submitted to the Data Path (DP)

    dp_msg_t *dp_msg = (dp_msg_t *)arg;
    dp_ctx_t *dp_ctx = (dp_ctx_t *)ev_dis->app_data;

    dp_uapi_trace_dp_msg (dp_ctx, dp_msg);

    switch (dp_msg->component_type) {

        case MAC_TABLE:
            dp_mac_table_process_msg (dp_ctx, dp_msg);
            break;
        case PKT_BLOCK:
            np_recv_cp_pkt_block (dp_ctx, dp_msg);
            break;
        case FIB_TABLE:
            dp_fib_table_process_msg (dp_ctx, dp_msg);
            break;
        case VRF_TABLE:
            dp_vrf_table_process_msg (dp_ctx, dp_msg);
            break;
        case INTF_TABLE:
            dp_intf_table_process_msg(dp_ctx, dp_msg);
            break;
        case DP_GENERICS:
            dp_generic_process_msg(dp_ctx, dp_msg);
            break;
        default:
            break;
    }
}