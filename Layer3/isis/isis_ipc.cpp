#include "../../tcp_public.h"
#include "isis_rtr.h"

extern  void 
 isis_interface_ipc_updates(node_t *node, uint32_t minor_code, ipc_interface_t *msg);
 
extern  void 
 isis_gre_tunnel_ipc_updates (node_t *node, uint32_t minor_code, ipc_gre_t *msg);

extern  void 
isis_access_lst_ipc_updates (node_t *node, uint32_t minor_code, ipc_access_lst_t *msg) ;

static void
isis_srv6_recv_ips_updates (node_t *node, uint32_t minor_code, ips_srv6_data_t *msg) {

    char buffer[48];
    char ipv4_addr_str[16];

    tracer (ISIS_TR(node), TR_ISIS_IPC,
        "Recvd SRv6 ips update, code = %u\n", minor_code);

    switch (minor_code ) {

        case  IPC_SRV6_LOCATOR_ADD:
        {
            tracer (ISIS_TR(node), TR_ISIS_IPC, 
                "Recv Locator ADD : %s/%d from node %s\n", 
                    inet_ntop6(&msg->u.locator.prefix, buffer), msg->u.locator.prefix_len,
                    tcp_ip_covert_ip_n_to_p (msg->rtr_id, (c_string)ipv4_addr_str));
        }
        break;
        case  IPC_SRV6_LOCATOR_DEL:
        {
            tracer (ISIS_TR(node), TR_ISIS_IPC, 
                "Recv Locator DEL : %s/%d from node %s\n", 
                    inet_ntop6(&msg->u.locator.prefix, buffer), msg->u.locator.prefix_len,
                    tcp_ip_covert_ip_n_to_p (msg->rtr_id, (c_string)ipv4_addr_str));
        }
        break;
        case IPC_SRV6_PREFIX_SID_ADD:
        {
            tracer (ISIS_TR(node), TR_ISIS_IPC, 
                "Recv PFX SID ADD : %s/%d from node %s\n", 
                    inet_ntop6(&msg->u.prefix_sid.prefix, buffer), msg->u.prefix_sid.prefix_len,
                    tcp_ip_covert_ip_n_to_p (msg->rtr_id, (c_string)ipv4_addr_str));
        }
        break;
        case IPC_SRV6_PREFIX_SID_DEL:
        {
            tracer (ISIS_TR(node), TR_ISIS_IPC, 
                "Recv PFX SID DEL : %s/%d from node %s\n", 
                    inet_ntop6(&msg->u.prefix_sid.prefix, buffer), msg->u.prefix_sid.prefix_len,
                    tcp_ip_covert_ip_n_to_p (msg->rtr_id, (c_string)ipv4_addr_str));
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
            isis_srv6_recv_ips_updates (node, minor_code, (ips_srv6_data_t *)msg);
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