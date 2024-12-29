#include "../../tcp_public.h"
#include "isis_rtr.h"
#include "isis_advt.h"
#include "isis_tlv_struct.h"
#include "isis_srv6.h"

extern  void 
 isis_interface_ipc_updates(node_t *node, uint32_t minor_code, ipc_interface_t *msg);
 
extern  void 
 isis_gre_tunnel_ipc_updates (node_t *node, uint32_t minor_code, ipc_gre_t *msg);

extern  void 
isis_access_lst_ipc_updates (node_t *node, uint32_t minor_code, ipc_access_lst_t *msg) ;

static void
isis_srv6_recv_ips_updates (node_t *node, uint32_t minor_code, ips_srv6_data_t *msg) {

    char ipv4_addr_str[16];
    char ipv6_addr_str[48];
    isis_advt_info_t advt_info;
    isis_adv_data_t *advt_data;

    isis_node_info_t *node_info = ISIS_NODE_INFO(node);

    tracer (ISIS_TR(node), TR_ISIS_IPC,
        "Recvd SRv6 ips update, code = %u\n", minor_code);

    switch (minor_code ) {

        case  IPC_SRV6_LOCATOR_ADD:
        {
            tracer (ISIS_TR(node), TR_ISIS_IPC, 
                "Recv Locator ADD : %s/%d from node %s\n", 
                    inet_ntop6(&msg->u.locator.prefix, ipv6_addr_str),
                     msg->u.locator.prefix_len,
                    tcp_ip_covert_ip_n_to_p (msg->rtr_id, (c_string)ipv4_addr_str));
 
            isis_srv6_advertise_locator (node,  msg ) ;
        }
        break;

        case  IPC_SRV6_LOCATOR_DEL:
        {
            tracer (ISIS_TR(node), TR_ISIS_IPC, 
                "Recv Locator DEL : %s/%d from node %s\n", 
                    inet_ntop6(&msg->u.locator.prefix, ipv6_addr_str), 
                    msg->u.locator.prefix_len,
                    tcp_ip_covert_ip_n_to_p (msg->rtr_id, (c_string)ipv4_addr_str));

            isis_srv6_stop_locator_advertisement (node);   
        }
        break;

        case IPC_SRV6_PREFIX_SID_ADD:
        {
            tracer (ISIS_TR(node), TR_ISIS_IPC, 
                "Recv PFX SID ADD : %s/128 from node %s\n", 
                    inet_ntop6(&msg->u.prefix_sid.prefix, ipv6_addr_str), 
                    tcp_ip_covert_ip_n_to_p (msg->rtr_id, (c_string)ipv4_addr_str));

                isis_add_prefix_sid_to_locator (node, msg); 
        }
        break;

        case IPC_SRV6_PREFIX_SID_DEL:
        {
            tracer (ISIS_TR(node), TR_ISIS_IPC, 
                "Recv PFX SID DEL : %s/128 from node %s\n", 
                    inet_ntop6(&msg->u.prefix_sid.prefix, ipv6_addr_str), 
                    tcp_ip_covert_ip_n_to_p (msg->rtr_id, (c_string)ipv4_addr_str));

                isis_delete_prefix_sid_from_locator (node, msg);
        }
        break;

        case IPC_SRV6_ADJ_SID_ADD:
        {

        }
        break;

        case IPC_SRV6_ADJ_SID_DEL:
        {

        }
        break;
    }
}

void isis_recv_ipc_updates (node_t *node, 
                                             ips_major_code_t major_code,
                                             uint32_t minor_code,
                                             void *msg,
                                             uint32_t msg_size) {

    switch (major_code) {

        case IPC_SRV6_INFO:
            {   
                isis_srv6_config_t *srv6_config = isis_srv6_get_config(node);
                if (!srv6_config) break;
                isis_srv6_recv_ips_updates (node, minor_code, (ips_srv6_data_t *)msg);
            }
        break;
        case IPC_INTERFACE:
            isis_interface_ipc_updates(node, minor_code, (ipc_interface_t *)msg);
        break;
        case IPC_GRE_TUNNEL:
            isis_gre_tunnel_ipc_updates (node, minor_code, (ipc_gre_t *)msg);
        break;
        case IPC_ACCESS_LIST:
            isis_access_lst_ipc_updates (node, minor_code, (ipc_access_lst_t *)msg);
        default: 
        ;
    }
}