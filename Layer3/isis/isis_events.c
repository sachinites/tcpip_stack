#include "isis_events.h"

static char isis_event_str_arr[isis_event_max][128] = 
{
    /* Warning : Order must match with enums */
    //isis_event_none
    "",
    //isis_event_adj_state_changed    
    "ISIS EVENT ADJ STATE CHANGED",
    //isis_event_admin_config_changed
    "ISIS EVENT ADMIN CONFIG CHANGED",
    //isis_event_nbr_attribute_changed
    "ISIS EVENT NBR ATTRIBUTE CHANGED",
    //isis_event_up_adj_deleted
    "ISIS EVENT UP ADJACENCY DELETED",
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
    //isis_event_lsp_time_out,
    "ISIS EVENT LSP TIMEOUT",
    //isis_event_periodic_lsp_generation
    "ISIS EVENT PERIODIC LSP GENERATION",
    //isis_event_admin_action_db_clear
    "ISIS EVENT ADMIN ACTION DB CLEAR",
    //isis_event_spf_job_scheduled,
    "ISIS EVENT SPF JOB SCHEDULED",
    //isis_event_spf_runs,
    "ISIS EVENT SPF RUNS",
    //isis_event_admin_Action_shutdown_pending
    "ISIS EVENT ADMIN ACTION SHUTDOWN PENDING",
    //isis_event_device_overload_config
    "ISIS EVENT DEVICE OVERLOAD BY ADMIN",
    //isis_event_device_dynamic_overload
    "ISIS EVENT DEVICE DYNAMIC OVERLOAD",
    //isis_event_overload_timeout
    "ISIS EVENT OVERLOAD TIMEOUT",
    //isis_event_route_rib_update
    "ISIS EVENT ROUTE RIB UPDATE",
    //isis_event_dis_changed
    "ISIS EVENT DIS CHANGED",
    //isis_event_discard_fragment
    "ISIS EVENT DISCARD FRAGMENT",
    //isis_event_fragment_regen
    "ISIS EVENT FRAGMENT REGEN",
    //isis_event_wait_list_tlv_advertised
    "ISIS EVENT WAIT LIST TLV ADVERTISED",
    //isis_event_tlv_wait_listed
    "ISIS EVENT TLV WAIT LISTED",
    //isis_event_tlv_added
    "ISIS EVENT TLV ADDED",
    //isis_event_tlv_removed
    "ISIS EVENT TLV REMOVED",
    //isis_event_full_lsp_regen
    "ISIS EVENT FULL LSP REGEN BIT"
}; 

const char *
isis_event_str(isis_event_type_t isis_event_type) {

    return isis_event_str_arr[isis_event_type];
}

unsigned long
isis_event_to_event_bit(isis_event_type_t event_type) {

    return (1 << event_type);
}
