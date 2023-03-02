#ifndef __ISIS_RTR_H__
#define __ISIS_RTR_H__
#include <stdbool.h>
#include "../../net.h"
#define ISIS_NODE_INFO(node_ptr) \
	((isis_node_info_t *)(node_ptr->node_nw_prop.isis_node_info))

typedef struct isis_node_info_
{

} isis_node_info_t;

typedef struct isis_timer_data_
{
	node_t *node;
	interface_t *intf;
	void *data;
	uint32_t data_size;
} isis_timer_data_t;

bool is_isis_protocol_enabled_on_node(node_t *node);

void isis_show_node_protocol_state(node_t *node);

#endif
