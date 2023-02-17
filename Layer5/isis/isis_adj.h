#ifndef __ISIS_ADJ__
#define __ISIS_ADJ__
#include "../../tcp_public.h"


typedef enum isis_adj_state_{
	ISIS_ADJ_STATE_UNKNOWN;
	ISIS_ADJ_STATE_DOWN;
	ISIS_ADJ_STATE_INIT;
	ISIS_ADJ_STATE_UP;
}isis_adj_state_t; 	

typedef struct isis_adjacency_{

	interface_t *intf;
        /*In Hello pkts these addresses are stored or defined as the uint32_t*/
	uint32_t nbr_rtr_id;

	uint32_t nbr_intf_id;

	uni32_t remote_if_index;

	uni32_t hold_time;

	unit32_t cost;

	isis_adj_state_t adj_state;

	time_t uptime;

	timer_event_handle *delete_timer;

	timer_event_handle *expiry_timer;

}isis_adjacency_t;

#endif
