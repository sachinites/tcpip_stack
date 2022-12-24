#ifndef __GREUAPI__
#define __GREUAPI__

class Interface;

bool
gre_tunnel_create (node_t *node, uint16_t tunnel_id) ;

bool
gre_tunnel_destroy (node_t *node, uint16_t tunnel_id) ;

void
gre_tunnel_set_src_addr (node_t *node, uint16_t tunnel_id, c_string src_addr);

void
gre_tunnel_unset_src_addr (node_t *node, uint16_t tunnel_id);

void
 gre_tunnel_set_src_interface (node_t *node, uint16_t gre_tun_id, c_string if_name);

 void
 gre_tunnel_unset_src_interface (node_t *node, uint16_t gre_tun_id);

#endif