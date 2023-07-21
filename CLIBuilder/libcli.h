#ifndef __LIBCLI__
#define __LIBCLI__

#include <ncurses.h>
#include "../stack/stack.h"
#include "KeyProcessor/KeyProcessor.h"
#include "CmdTree/CmdTree.h"
#include "cmdtlv.h"

int cprintf (const char* format, ...) ;

void
libcli_init ();

/*See the definition of this fn to know about arguments*/
void
init_param(param_t *param,    
           param_type_t param_type,    
           const char *cmd_name,    
           cmd_callback callback,
           user_validation_callback user_validation_cb_fn,
           leaf_type_t leaf_type,
           const char *leaf_id,
           const char *help);

void 
libcli_register_param (param_t *parent, param_t *child);

void 
libcli_set_param_cmd_code (param_t *param, int cmd_code) ;

void
libcli_support_cmd_negation (param_t *param);

void 
libcli_param_recursive (param_t *param);

void 
libcli_param_match_regex(param_t *param, char *reg_ex);

static inline bool
parser_match_leaf_id (unsigned char *tlv_leaf_id, const char *leaf_id_manual) {

    size_t len;
    if ((len = strlen((const char *)tlv_leaf_id)) != strlen(leaf_id_manual)) return false;
    return (strncmp((const char *)tlv_leaf_id, leaf_id_manual, len) == 0); 
}

void
libcli_register_display_callback (param_t *param, display_possible_values_callback cbk);

void 
libcli_set_tail_config_batch_processing (param_t *param);

void 
libcli_init_done ();

void
cli_start_shell();

void cli_register_ctrlC_handler(void (*fn_ptr)(void));

#endif
