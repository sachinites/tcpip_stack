#include "isis_events.h"

static char isis_event_str_arr[isis_event_max][128] = 
{
    /* Warning : Order must match with enums */
    //isis_event_none
    "",
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
    "ISIS EVENT NON LOCAL OLD LSP"
} ;

const char *
isis_event_str(isis_event_type_t isis_event_type) {

    return isis_event_str_arr[isis_event_type];
}