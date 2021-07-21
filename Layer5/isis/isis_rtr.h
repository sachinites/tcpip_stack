#ifndef __ISIS_RTR__
#define __ISIS_RTR__

bool
isis_node_is_enable(node_t *node) ;

void
isis_init(node_t *node );

void
isis_de_init(node_t *node) ;

void
isis_protocol_shut_down(node_t *node);

#endif