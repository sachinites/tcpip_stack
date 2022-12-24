#ifndef __GRESTRUCT__
#define __GRESTRUCT__

#include <stdint.h>
#include <stdbool.h>

#include "../../graph.h"
typedef struct pkt_block_ pkt_block_t;
class Interface;

bool
gre_tunnel_activate (node_t *node, Interface *tunnel_intf);

void
gre_tunnel_deactivate (node_t *node, Interface *tunnel_intf);

void
gre_tunnel_send_pkt_out (node_t *node, Interface *tunnel_intf, pkt_block_t *pkt_block);

#endif 
