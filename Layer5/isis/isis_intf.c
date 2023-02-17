#ifndef __ISIS_INTF_C__
#define __ISIS_INTF_C__
#include <assert.h>
#include "../../tcp_public.h"
#include <stdbool.h>
#include "isis_intf.h"
typedef struct isis_intf_info_
{
	uint32_t cost; // Represents the cost associated with the interface

	uint32_t hello_interval; // Hello pkts time interval in seconds

} isis_intf_info_t;

static void
isis_init_isis_intf_info(interface *intf)
{
	isis_intf_info_t *isis_intf_info = ISIS_INTF_INFO(intf);
	memset(isis_inft_info, 0, sizeof(isis_intf_info_t));
	isis_intf_info_t->hello_interval = ISIS_DEFAULT_HELLO_INTERVAL;
	isis_intf_info_t->cost = ISIS_DEFAULT_INTF_COST;
}

bool is_isis_procotol_enabled_on_interface(interface_t *intf)
{
	isis_intf_info_t *isis_intf_info = ISIS_INTF_INFO(intf);

	if (!isis_intf_info)
	{

		return false;
	}

	return true;
}

void isis_config_enable_on_intf(interface_t *intf)
{
	/*Check whether the ISIS protocol is enabled on the node or not */

	if (intf->att_node->node_nw_prop.isis_node_info == NULL)
	{
		printf("First enable ISIS protocol on Node %s\n", intf->att_node->node_name);
		return;
	}

	isis_intf_info_t *isis_intf_info = ISIS_INTF_INFO(intf);
	if (isis_intf_info)
	{
		return;
	}

	isis_intf_info = calloc(1, sizeof(isis_intf_info_t));
	// isis_init_isis_intf_info();
	intf->intf_nw_props.isis_intf_info = isis_intf_info;
	isis_init_isis_intf_info(intf);
}

void isis_config_disable_on_intf(interface_t *intf)
{
	isis_intf_info_t *isis_intf_info = ISIS_INTF_INFO(intf);
	if (!isis_intf_info)
	{
		return;
	}
	free(isis_intf_info);
	intf->intf_nw_props.isis_intf_info = NULL;
}

void isis_show_intf_protocol_state(interface_t *intf)
{
	printf("%s: %s\n",
		   intf->if_name, is_isis_procotol_enabled_on_interface(intf) ? "Enabled" : "Disabled");
}

#endif
