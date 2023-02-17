#ifndef __ISIS_PKT_H__
#define __ISIS_PKT_H__

#define ISIS_INTF_COST(intf_ptr)  \
			( (intr_ptr)->intf_nw_props.isis_intf_info.cost)
#define ISIS_INTF_HELLO_INTERVAL(intf_ptr)  \
			( (intr_ptr)->intf_nw_props.isis_intf_info.hello_interval)

bool
isis_pkt_trap_rule(char *pkt, size_t pkt_size);
bool
isis_pkt_receive(void *arg, size_t *size)

#endif
