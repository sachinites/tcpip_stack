#ifndef __CMDTREE_CURSOR__
#define __CMDTREE_CURSOR__

typedef struct cmd_tree_cursor_ cmd_tree_cursor_t;
typedef struct cli_ cli_t;
typedef struct stack Stack_t;

void 
cmd_tree_cursor_init (cmd_tree_cursor_t **cmdtc);

 cmdt_cursor_op_res_t
 cmdt_cursor_parse_next_char (cmd_tree_cursor_t *cmdtc, unsigned char c);

void 
cmd_tree_cursor_deinit (cmd_tree_cursor_t *cmdtc) ;

void 
cmd_tree_init_cursors () ;

bool
cmdtc_get_cmd_trigger_status (cmd_tree_cursor_t *cmdtc);

cmd_tree_cursor_t *
cmdtc_tree_get_cursor ();

void 
cmd_tree_cursor_move_to_next_level (cmd_tree_cursor_t *cmdtc) ;

bool
cmd_tree_cursor_move_one_char_back (cmd_tree_cursor_t *cmdtc);

int
cmd_tree_cursor_move_one_level_up (cmd_tree_cursor_t *cmdtc,
                                                                bool honor_checkpoint, bool update_root) ;

void 
cmd_tree_cursor_destroy_internals (cmd_tree_cursor_t *cmdtc, bool free_tlvs);

void 
cmdtc_process_question_mark (cmd_tree_cursor_t *cmdtc);

const char *
cmdtc_get_state_str (cmd_tree_cursor_t *cmdtc);

void 
cmd_tree_enter_mode (cmd_tree_cursor_t *cmdtc);

bool
cmd_tree_process_carriage_return_key (cmd_tree_cursor_t *cmdtc) ;

bool 
cmdtc_is_cursor_at_bottom_mode_node (cmd_tree_cursor_t *cmdtc);

bool 
cmdtc_is_cursor_at_apex_root (cmd_tree_cursor_t *cmdtc);

bool
cmdtc_parse_full_command (cli_t *cli);

void 
cmd_tree_cursor_reset_for_nxt_cmd (cmd_tree_cursor_t *cmdtc) ;

Stack_t *
cmdtc_get_params_stack (cmd_tree_cursor_t *cmdtc);

Stack_t *
cmdtc_get_tlv_stack (cmd_tree_cursor_t *cmdtc);

param_t *
cmdtc_get_root (cmd_tree_cursor_t *cmdtc);

void
cmdtc_display_all_complete_commands (cmd_tree_cursor_t *cmdtc);

int
cmdtc_process_pageup_event (cmd_tree_cursor_t *cmdtc);

void
cmdtc_debug_print_stats (cmd_tree_cursor_t *cmdtc);

 bool 
 cmdtc_am_i_working_in_mode (cmd_tree_cursor_t *cmdtc) ;

 bool 
 cmdtc_am_i_working_in_nested_mode (cmd_tree_cursor_t *cmdtc) ;

bool 
cmdtc_is_params_stack_empty (Stack_t *stack);

bool 
cmdtc_is_tlv_stack_empty (Stack_t *tlv_stack) ;

param_t *
cmdtc_get_branch_hook (cmd_tree_cursor_t *cmdtc);

bool
cmdtc_parse_raw_command (unsigned char *command, int cmd_size) ;


#endif 