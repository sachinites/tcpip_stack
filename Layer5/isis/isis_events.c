#include "isis_events.h"

static char isis_event_str[isis_event_max][128] = 
{
    /* Warning : Order must match with enums */
    //isis_event_none
    "",
    //isis_event_adj_state_goes_up    
    "ISIS ADJ GOES UP",
    //isis_event_adj_state_goes_down
    "ISIS ADJ GOES DOWN",
    //isis_event_protocol_enable
    "ISIS PROTOCOL ENABLED",
    //isis_event_protocol_disable
    "ISIS PROTOCOL DISABLED",
    //isis_event_protocol_disable_on_intf
    "ISIS INTF DISABLED",
    //isis_event_protocol_enable_on_intf
    "ISIS INTF ENABLED",
    //isis_nbr_ip_changed
    "ISIS NBR IP CHANGED",
    //isis_nbr_metric_changed
    "ISIS NBR METRIC CHANGED",
    //isis_nbr_rtr_id_changed
    "ISIS NBR RTR ID CHANGED"
}; 

const char *
isis_event(isis_events_t isis_event_type) {

    return isis_event_str[isis_event_type];
}