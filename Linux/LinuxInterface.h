#ifndef __LOAD_INTF__
#define __LOAD_INTF__

#include "../Interface/InterfaceFwd.h"

typedef struct node_ node_t;
typedef struct pkt_block_ pkt_block_t;


#define LINUX_PKT_SKT_BUFFER_SIZE 2048
#define LINUX_MGMT_INTERFACE "ens3"

void 
LinuxLoadInterfaces (node_t *node);

int
linux_send_xmit_out (Interface *intf, pkt_block_t *pkt_block);

void
Linux_listen_interfaces (node_t *node);

#endif 
