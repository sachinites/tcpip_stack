#include "../../tcp_public.h"

extern  void 
 isis_interface_ipc_updates(node_t *node, uint32_t minor_code, ipc_interface_t *msg);
 
extern  void 
 isis_gre_tunnel_ipc_updates (node_t *node, uint32_t minor_code, ipc_gre_t *msg);

extern  void 
isis_access_lst_ipc_updates (node_t *node, uint32_t minor_code, ipc_access_lst_t *msg) ;

void isis_recv_ipc_updates (node_t *node, 
                                             ips_major_code_t major_code,
                                             uint32_t minor_code,
                                             void *msg,
                                             uint32_t msg_size) {

    switch (major_code) {

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