#include "isis_events.h"

static char isis_event_str_arr[isis_event_max][128] = 
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
    "ISIS NBR RTR ID CHANGED",
    /*lspdb update events*/
    //isis_event_self_duplicate_lsp,
    "ISIS EVENT SELF DUPLICATE LSP",
    //isis_event_self_fresh_lsp,
    "ISIS EVENT SELF FRESH LSP",
    //isis_event_self_new_lsp,
    "ISIS EVENT SELF NEW LSP",
    //isis_event_self_old_lsp,
    "ISIS EVENT SELF OLD LSP",
    //isis_event_non_local_duplicate_lsp,
    "ISIS EVENT NON LOCAL DUPLICATE LSP",
    //isis_event_non_local_fresh_lsp,
    "ISIS EVENT NON LOCAL FRESH LSP",
    //isis_event_non_local_new_lsp,
    "ISIS EVENT NON LOCAL NEW LSP",
    //isis_event_non_local_old_lsp,
    "ISIS EVENT NON LOCAL OLD LSP",
    //isis_event_on_demand_flood
    "ISIS EVENT ON DEMAND FLOOD",
    //isis_event_periodic_lsp_generation
    "ISIS EVENT PERIODIC LSP GENERATION",
    //isis_event_admin_action
    "ISIS EVENT ADMIN ACTION"
}; 

const char *
isis_event_str(isis_event_type_t isis_event_type) {

    return isis_event_str_arr[isis_event_type];
}