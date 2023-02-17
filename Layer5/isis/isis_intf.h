#ifndef __ISIS_INTF_H__
#define __ISIS_INTF_H__
#include "isis_consh.h"

#define ISIS_INTF_INFO(intf_ptr)    \
	((isis_intf_info_t *)((intf_ptr)->intf_nw_props.isis_intf_info))

void
isis_config_enable_on_intf(interface_t *intf);

void
isis_config_disable_on_intf(interface_t *intf);

void 
isis_show_intf_protocol_state(interface_t *intf);

static void 
isis_init_isis_intf_info(interface *intf);
#endif
