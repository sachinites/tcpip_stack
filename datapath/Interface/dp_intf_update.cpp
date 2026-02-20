#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include "../../common/cp2dp.h"
#include "../../Tracer/tracer.h"
#include "dp_intf.h"
#include "dp_intf_update.h"
#include "dp_intf_store.h"
#include "../Vrfs/dp_vrf.h"

void 
dp_intf_table_process_msg(node_t *node, dp_msg_t *dp_msg){

    dp_intf_t *intf = NULL;
    char ip_str[INET_ADDRSTRLEN];
    char ipv6_str[INET6_ADDRSTRLEN];
    hashtable_t *ht = node->dp_intf_ht;

    assert (dp_msg->component_type == INTF_TABLE);

    switch (dp_msg->opr_type) {

        case DP_CREATE:
        {
            dp_intf_cp2dp_msg_t *msg = 
                (dp_intf_cp2dp_msg_t *)dp_msg->data;

            tracer(node->dptr, DCONF, 
                "Creating interface port_id=%u iftype=%u\n",
                msg->port_id, msg->iftype);

            intf = dp_look_up_interface(ht, msg->port_id);
            assert (!intf);
            intf = dp_create_interface(msg->port_id, msg->iftype, &msg->mac_addr);
            strncpy(intf->if_name, msg->intf_name, sizeof (msg->intf_name));
            dp_insert_interface(ht, intf);
            
            tracer(node->dptr, DCONF, 
                "Interface port_id=%u created successfully\n",
                msg->port_id);
        }   
        break;

        case DP_DEL:
        {
            dp_intf_cp2dp_msg_t *msg = 
                (dp_intf_cp2dp_msg_t *)dp_msg->data;
            
            tracer(node->dptr, DCONF, 
                "Deleting interface port_id=%u\n",
                msg->port_id);
            
            dp_delete_interface(ht, msg->port_id);
            
            tracer(node->dptr, DCONF, 
                "Interface port_id=%u deleted\n",
                msg->port_id);
        }
        break;

        case DP_UPDATE:
        {
            dp_intf_cp2dp_msg_t *msg = 
                (dp_intf_cp2dp_msg_t *)dp_msg->data;

            intf = dp_look_up_interface(ht, msg->port_id);
            assert (intf);

            /* Process update based on update_code */
            switch (msg->update_code) {

                case CP2DP_CODE_INTF_IPV4_ADDR:
                {
                    dp_intf_ipv4_addr_update_t *ipv4_update = 
                        (dp_intf_ipv4_addr_update_t *)(msg + 1);
                    
                    struct in_addr addr;
                    addr.s_addr = ipv4_update->ipv4_addr;
                    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
                    
                    tracer(node->dptr, DCONF, 
                        "Updating IPv4 address on port_id=%u to %s/%u\n",
                        msg->port_id, ip_str, ipv4_update->mask);
                    
                    intf->ip_addr = ipv4_update->ipv4_addr;
                    intf->mask = ipv4_update->mask;
                }
                break;

                case CP2DP_CODE_INTF_IPV6_ADDR:
                {
                    dp_intf_ipv6_addr_update_t *ipv6_update = 
                        (dp_intf_ipv6_addr_update_t *)(msg + 1);
                    
                    inet_ntop(AF_INET6, ipv6_update->ipv6_addr, ipv6_str, sizeof(ipv6_str));
                    
                    tracer(node->dptr, DCONF, 
                        "Updating IPv6 address on port_id=%u to %s/%u\n",
                        msg->port_id, ipv6_str, ipv6_update->prefix_len);
                    
                    memcpy(intf->v6addr, ipv6_update->ipv6_addr, 16);
                    intf->v6mask = ipv6_update->prefix_len;
                }
                break;

                case CP2DP_CODE_INTF_VLAN_BIND:
                {
                    dp_intf_vlan_bind_t *vlan_bind = 
                        (dp_intf_vlan_bind_t *)(msg + 1);
                    
                    tracer(node->dptr, DCONF, 
                        "Binding VLAN on port_id=%u vlan_port_id=%u l2_mode=%d\n",
                        msg->port_id, vlan_bind->vlan_port_id, vlan_bind->l2_mode);
                    
                    /* Look up the VLAN interface */
                    dp_intf_t *vlan_intf = dp_look_up_interface(ht, vlan_bind->vlan_port_id);
                    
                    intf->vlan_intf = vlan_intf;
                    intf->vlan_id = vlan_bind->vlan_port_id;
                    intf->l2_mode = vlan_bind->l2_mode;
                    intf->switchport = true;
                }
                break;

                case CP2DP_CODE_INTF_ADMIN_DOWN:
                {
                    dp_intf_admin_down_t *admin_down = 
                        (dp_intf_admin_down_t *)(msg + 1);
                    
                    tracer(node->dptr, DCONF, 
                        "Setting admin status on port_id=%u to %s\n",
                        msg->port_id, admin_down->status ? "DOWN" : "UP");
                    
                    intf->is_up = !admin_down->status;  /* status true means down, so invert */
                }
                break;

                case CP2DP_CODE_INTF_VRF_BIND:
                {
                    dp_intf_vrf_bind_t *vrf_bind = 
                        (dp_intf_vrf_bind_t *)(msg + 1);
                    
                    tracer(node->dptr, DCONF, 
                        "Binding interface port_id=%u to VRF vrf_id=%u\n",
                        vrf_bind->port_id, vrf_bind->vrf_id);
                    
                    /* Look up VRF by vrf_id and assign to intf->vrf */
                    dp_vrf_t *vrf = dp_look_up_vrf(node->dp_vrf_ht, vrf_bind->vrf_id);
                    dp_intf_t *intf = dp_look_up_interface(ht, vrf_bind->port_id);
                    assert (vrf && intf && !(intf->vrf));
                    intf->vrf = vrf;
                    
                    tracer(node->dptr, DCONF, 
                        "Interface port_id=%u successfully bound to VRF %s\n",
                        vrf_bind->port_id, vrf->vrf_name);
                }
                break;

                default:
                    tracer(node->dptr, DCONF, 
                        "Unknown update code %u for port_id=%u\n",
                        msg->update_code, msg->port_id);
                    break;
            }
        }
        break;

        case DP_READ:
            tracer(node->dptr, DCONF, "Read operation (not implemented)\n");
            break;

        case DP_L3_NORTHBOUND_IN:
            tracer(node->dptr, DCONF, "L3 northbound operation (not applicable)\n");
            break;

        default:
            tracer(node->dptr, DCONF, "Unknown operation type %d\n", dp_msg->opr_type);
            break;
    }

EXIT:
    cp2dp_msg_free(dp_msg);
}

/* Interface update message sending functions */

void 
cp2dp_send_intf_ipv4_addr_update(node_t *node, uint32_t port_id, uint32_t ipv4_addr, uint8_t mask) {
    
    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_t *intf_msg;
    dp_intf_ipv4_addr_update_t *ipv4_update;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_t) + sizeof(dp_intf_ipv4_addr_update_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_t *)dp_msg->data;
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
    dp_intf_cp2dp_msg_t *intf_msg;
    dp_intf_ipv6_addr_update_t *ipv6_update;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_t) + sizeof(dp_intf_ipv6_addr_update_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_t *)dp_msg->data;
    intf_msg->port_id = port_id;
    intf_msg->update_code = CP2DP_CODE_INTF_IPV6_ADDR;
    
    /* Fill in the IPv6 update data */
    ipv6_update = (dp_intf_ipv6_addr_update_t *)(intf_msg + 1);
    memcpy(ipv6_update->ipv6_addr, ipv6_addr, 16);
    ipv6_update->prefix_len = prefix_len;
    
    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_send_intf_vlan_bind_update(node_t *node, uint32_t port_id, uint32_t vlan_port_id, DP_IntfL2Mode l2_mode) {
    
    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_t *intf_msg;
    dp_intf_vlan_bind_t *vlan_bind;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_t) + sizeof(dp_intf_vlan_bind_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_t *)dp_msg->data;
    intf_msg->port_id = port_id;
    intf_msg->update_code = CP2DP_CODE_INTF_VLAN_BIND;
    
    /* Fill in the VLAN bind data */
    vlan_bind = (dp_intf_vlan_bind_t *)(intf_msg + 1);
    vlan_bind->port_id = port_id;
    vlan_bind->vlan_port_id = vlan_port_id;
    vlan_bind->l2_mode = l2_mode;
    
    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_send_intf_admin_status_update(node_t *node, uint32_t port_id, bool is_down) {
    
    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_t *intf_msg;
    dp_intf_admin_down_t *admin_down;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_t) + sizeof(dp_intf_admin_down_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_t *)dp_msg->data;
    intf_msg->port_id = port_id;
    intf_msg->update_code = CP2DP_CODE_INTF_ADMIN_DOWN;
    
    /* Fill in the admin status data */
    admin_down = (dp_intf_admin_down_t *)(intf_msg + 1);
    admin_down->port_id = port_id;
    admin_down->status = is_down;
    
    cp2dp_submit(node, dp_msg, true);
}

void 
cp2dp_send_intf_vrf_bind_update(node_t *node, uint32_t port_id, uint16_t vrf_id) {
    
    dp_msg_t *dp_msg;
    dp_intf_cp2dp_msg_t *intf_msg;
    dp_intf_vrf_bind_t *vrf_bind;

    dp_msg = cp2dp_msg_alloc();
    dp_msg->component_type = INTF_TABLE;
    dp_msg->opr_type = DP_UPDATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(dp_intf_cp2dp_msg_t) + sizeof(dp_intf_vrf_bind_t);
    
    /* Fill in the header */
    intf_msg = (dp_intf_cp2dp_msg_t *)dp_msg->data;
    intf_msg->port_id = port_id;
    intf_msg->update_code = CP2DP_CODE_INTF_VRF_BIND;
    
    /* Fill in the VRF bind data */
    vrf_bind = (dp_intf_vrf_bind_t *)(intf_msg + 1);
    vrf_bind->port_id = port_id;
    vrf_bind->vrf_id = vrf_id;
    
    cp2dp_submit(node, dp_msg, true);
}