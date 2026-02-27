#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include "../../common/cp2dp.h"
#include "../../Tracer/tracer.h"
#include "dp_intf.h"
#include "dp_intf_update.h"
#include "dp_intf_store.h"
#include "../Vrfs/dp_vrf.h"
#include "../../Interface/Interface.h"
#include "../../Layer2/vxlan/dp/vlan_vni_ht.h"
#include "../../Layer2/transport_svc.h"
#include "../dp_ctx.h"

static inline bool 
dp_bitmap_at(uint8_t *bit_array, uint16_t index) {

    uint16_t n_blocks = index / 32;
    uint8_t bit_pos = index % 32;
    uint32_t *ptr = (uint32_t *)(bit_array) + n_blocks;
    return htonl(*ptr) & (1 << (32 - bit_pos - 1));  
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
                case 0:
                    dp_insert_interface(ht, intf);
                    break;
                case INTF_TYPE_RMAC:
                    dp_ctx->dp_rmac_intf = intf;
                    break;
                case INTF_TYPE_VLAN_FLOOD:
                    dp_ctx->dp_vlan_flood_intf = intf;
                    break;
                case INTF_TYPE_NVE:
                    dp_ctx->dp_nve_intf = intf;
                    break;
                case INTF_TYPE_SRv6:
                    dp_ctx->dp_srv6_end_intf = intf;
                    break;
                case INTF_TYPE_HOST_PATH:
                    dp_ctx->dp_host_path_intf = intf;
                    break;
                default: 
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
            else if (msg->port_id == dp_ctx->dp_srv6_end_intf->port_id) {
                dp_check_and_free_interface(dp_ctx->dp_srv6_end_intf);
                dp_ctx->dp_srv6_end_intf = NULL;
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
                        dp_vlan_bind_port (vlan_intf, intf, vlan_bind->l2_mode);
                    }
                    else {
                        dp_vlan_unbind_port (vlan_intf, intf, vlan_bind->l2_mode, true);
                    }
                    tracer(dp_ctx->dptr, DCONF, 
                        "%sBinding %s with %s l2_mode=%s\n",
                        vlan_bind->add ? "" : "Un",
                        vlan_intf->if_name, intf->if_name,
                        dp_intf_mode_str(vlan_bind->l2_mode));
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

                case CP2DP_CODE_INTF_VRF_BIND:
                {
                    dp_intf_vrf_bind_t *vrf_bind = 
                        (dp_intf_vrf_bind_t *)(msg + 1);
                    
                    tracer(dp_ctx->dptr, DCONF, 
                        "Binding interface if_name=%s to VRF vrf_id=%d\n",
                        intf->if_name, vrf_bind->vrf_id);
                    
                    /* Look up VRF by vrf_id and assign to intf->vrf */
                    dp_vrf_t *vrf = dp_look_up_vrf(dp_ctx->dp_vrf_ht, vrf_bind->vrf_id);
                    dp_intf_t *intf = dp_look_up_interface(ht, vrf_bind->port_id);

                    if (vrf) {
                        /* We are binding interface to vrf*/
                        assert (!intf->vrf);
                        intf->vrf = vrf;
                                            
                        tracer(dp_ctx->dptr, DCONF, 
                            "Interface intf=%s successfully bound to VRF %s\n",
                            intf->if_name, vrf->vrf_name);
                    }
                    else if (vrf_bind->vrf_id == -1){
                        /* We are unbinding interface to vrf*/
                        assert (intf->vrf);
                        intf->vrf = NULL;
                    
                        tracer(dp_ctx->dptr, DCONF, 
                         "Interface intf=%s successfully unbound from VRF %s\n",
                            intf->if_name, vrf->vrf_name);                        
                    }
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

/* Interface update message sending functions */

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
                                 DP_IntfL2Mode l2_mode,
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
    vlan_bind->l2_mode = l2_mode;
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
    dp_intf_switchpor_t *sw_status;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t) + sizeof(dp_intf_switchpor_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = port_id;
    intf_msg->update_code = CP2DP_CODE_INTF_SW;
    
    /* Fill in the admin status data */
    sw_status = (dp_intf_switchpor_t *)(intf_msg + 1);
    sw_status->port_id = port_id;
    sw_status->enable = switchport;
    
    cp2dp_submit(node, dp_msg, true);    
}

void 
cp2dp_send_intf_vrf_bind_update(node_t *node, uint32_t port_id, int32_t vrf_id) {
    
    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;
    dp_intf_vrf_bind_t *vrf_bind;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t) + sizeof(dp_intf_vrf_bind_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = port_id;
    intf_msg->update_code = CP2DP_CODE_INTF_VRF_BIND;
    
    /* Fill in the VRF bind data */
    vrf_bind = (dp_intf_vrf_bind_t *)(intf_msg + 1);
    vrf_bind->port_id = port_id;
    vrf_bind->vrf_id = vrf_id;
    
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
        case INTF_TYPE_SRv6:
            intf_msg->update_code = CP2DP_CODE_INTF_SRV6_END;
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
cp2dp_interface_delete (node_t *node, Interface *intf) {

    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_hdr_t *intf_msg;

    assert (intf->iftype != INTF_TYPE_PHY);

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_hdr_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_hdr_t *)dp_msg->data;
    intf_msg->port_id = intf->ifindex;
    intf_msg->iftype = (uint32_t)intf->iftype;
    intf_msg->update_code = 0;
    
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
