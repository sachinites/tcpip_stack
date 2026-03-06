#include <stdint.h>
#include "cp_ipc_struct.h"
#include "cp_ipc.h"


typedef struct node_ node_t;
typedef struct isis_node_info_ isis_node_info_t;

extern void
isis_recv_ipc_updates(isis_node_info_t *node_info,
                      ips_major_code_t major_code,
                      uint32_t minor_code,
                      void *msg,
                      uint32_t msg_size);

static void
isis_init_ips_pub_sub(node_t *node)
{
    cp_ips_join(node, IPC_INTERFACE,
                IPC_INTERFACE_ADD |
                    IPC_INTERFACE_DEL |
                    IPC_INTERFACE_IPV4_ADDR_ADD |
                    IPC_INTERFACE_IPV4_ADDR_DEL |
                    IPC_INTERFACE_IPV4_ADDR_UPDATE |
                    IPC_INTERFACE_IPV6_ADDR_ADD |
                    IPC_INTERFACE_IPV6_ADDR_DEL |
                    IPC_INTERFACE_IPV6_ADDR_UPDATE |
                    IPC_INTERFACE_ADMIN_STATE_DOWN |
                    IPC_INTERFACE_ADMIN_STATE_UP |
                    IPC_INTERFACE_METRIC_UPDATE,
                isis_recv_ipc_updates);
    cp_ips_join(node, IPC_GRE_TUNNEL, IPC_ALL_MINOR_UPDATES,
                isis_recv_ipc_updates);
    cp_ips_join(node, IPC_ACCESS_LIST, IPC_ALL_MINOR_UPDATES,
                isis_recv_ipc_updates);
}

void 
cp_init_ipc_pub_sub(node_t *node) {

    isis_init_ips_pub_sub(node);
}