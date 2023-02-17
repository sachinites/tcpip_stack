#include <assert.h>
#include "isis_rtr.h"
#include <stdbool.h>
#include "../../tcp_public.h"

bool is_isis_protocol_enabled_on_node(node_t *node)
{

	isis_node_info_t *isis_node_info = ISIS_NODE_INFO(node);
	if(!isis_node_info)
	{

		printf("Printing false \n");
		return false;
	}

	printf("Printing true \n");
	return true;
}

void isis_show_node_protocol_state(node_t *node)
{
	printf("ISIS Protocol : %s\n",
		   is_isis_protocol_enabled_on_node(node) ? "Enabled" : "Disabled");
}
