#ifndef __ISIS_INTF_C__
#define __ISIS_INTF_C__
#include <assert.h>
#include "../../tcp_public.h"
#include <stdbool.h>
#include "isis_intf.h"
static void isis_init_isis_intf_info(interface_t *intf)
{
	isis_intf_info_t *isis_intf_info = ISIS_INTF_INFO(intf);
	memset(isis_intf_info, 0, sizeof(isis_intf_info_t));
	isis_intf_info->hello_interval = ISIS_DEFAULT_HELLO_INTERVAL;
	isis_intf_info->cost = ISIS_DEFAULT_INTF_COST;
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

static void isis_transmit_hello(void *arg, uint32_t arg_size)
{

	if (arg != NULL)
	{
		return;
	}

	isis_timer_data_t *isis_timer_data = (isis_timer_data_t *)arg;

	node_t *node = isis_timer_data->node;
	interface_t *intf = isis_timer_data->intf;
	byte *hello_pkt = (byte *)isis_timer_data->data;
	uint32_t pkt_size = isis_timer_data->data_size;

	send_pkt_out(hello_pkt, pkt_size, intf);
}

void isis_start_sending_hellos(interface_t *intf)
{

	node_t *node;
	uint32_t hello_pkt_size;

	wheel_timer_t *wt = node_get_timer_instance(node);
	byte *hello_pkt = isis_prepare_hello_pkt(intf, &hello_pkt_size);
	isis_timer_data_t *isis_timer_data;

	isis_timer_data->node = intf->att_node;
	isis_timer_data->intf = intf;
	isis_timer_data->data = (void *)hello_pkt;
	isis_timer_data->data_size = hello_pkt_size;

	ISIS_INTF_HELLO_XMIT_TIMER(intf) = timer_register_app_event(wt,
			isis_transmit_hello,
			(void *)isis_timer_data,
			sizeof(isis_timer_data_t),
			ISIS_INTF_HELLO_INTERVAL(intf) * 1000,
			1);
}

void isis_stop_sending_hellos(interface_t *intf)
{
		timer_event_handle *hello_xmit_timer=NULL;

		hello_xmit_timer = ISIS_INTF_HELLO_XMIT_TIMER(intf);

		if(!hello_xmit_timer)return;

		isis_timer_data_t *isis_timer_data = (isis_timer_data_t *)wt_elem_get_and_set_app_data(hello_xmit_timer, 0);

		tcp_ip_free_pkt_buffer(isis_timer_data->data, isis_timer_data->data_size);

		timer_de_register_app_event(hello_xmit_timer);
		
		ISIS_INTF_HELLO_XMIT_TIMER(intf)=NULL;
}

#endif
