#ifndef __ISIS_INTF_H__
#define __ISIS_INTF_H__
#include "isis_pkt.h"
#include "isis_const.h"
#include "isis_rtr.h"

typedef struct isis_intf_info_
{
	uint32_t cost; // Represents the cost associated with the interface

	uint32_t hello_interval; // Hello pkts time interval in seconds

	timer_event_handle *hello_xmit_timer;

} isis_intf_info_t;



#define ISIS_INTF_INFO(intf_ptr)    \
	((isis_intf_info_t *)((intf_ptr)->intf_nw_props.isis_intf_info))

#define ISIS_INTF_COST(intf_ptr)  \
			(ISIS_INTF_INFO(intf_ptr)->cost)

#define ISIS_INTF_HELLO_INTERVAL(intf_ptr)  \
			( ISIS_INTF_INFO(intf_ptr)->hello_interval)

#define ISIS_INTF_HELLO_XMIT_TIMER(intf_ptr)  \
			 (ISIS_INTF_INFO(intf_ptr)->hello_xmit_timer)
void
isis_config_enable_on_intf(interface_t *intf);

void
isis_config_disable_on_intf(interface_t *intf);

void 
isis_show_intf_protocol_state(interface_t *intf);

static void 
isis_init_isis_intf_info(interface_t *intf);

void 
isis_start_sending_hellos(interface_t *intf);

void 
isis_stop_sending_hellos(interface_t *intf);
#endif
