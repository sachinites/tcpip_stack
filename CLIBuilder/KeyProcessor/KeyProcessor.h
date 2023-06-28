#ifndef __KEY_PROCESSOR__
#define __KEY_PROCESSOR__

#include  <stdbool.h>
#include <stdint.h>

typedef struct cli_ cli_t;
typedef struct cli_history_ cli_history_t;
typedef struct cmd_tree_cursor_ cmd_tree_cursor_t;

#include "../CmdTree/CmdTreeEnums.h"

void cli_content_reset (cli_t *cli);

void cli_complete_reset (cli_t *cli);

void cli_printsc (cli_t *cli, bool next_line) ;

bool 
cli_is_char_mode_on () ;

cli_t * cli_get_default_cli () ;

cli_t *cli_malloc ();

void cli_set_default_cli (cli_t *cli) ;

void cli_set_hdr (cli_t *cli, unsigned char *new_hdr, uint8_t size);

unsigned char *cli_get_cli_buffer (cli_t *cli, int *size);

unsigned char *cli_get_user_command (cli_t *cli, int *size);

int cli_append_user_command (cli_t *cli, unsigned char *cmd, int size) ;

void cli_set_cmd_tree_cursor (cli_t *cli, cmd_tree_cursor_t *cmdtc) ;

bool
cli_cursor_is_at_end_of_line (cli_t *cli);

bool
cli_cursor_is_at_begin_of_line (cli_t *cli);

void 
cli_content_shift_right (cli_t *cli);

void 
cli_content_shift_left (cli_t *cli);

void 
cli_record_cli_history (cli_history_t *cli_history, cli_t *new_cli);

bool 
cli_is_prev_char (cli_t *cli, unsigned char ch);

void
cli_screen_cursor_move_next_line ();

void 
cli_screen_cursor_move_cursor_right (int cols) ;

void 
cli_screen_cursor_move_cursor_left (int cols, bool remove_char);

void
cli_screen_cursor_save_screen_pos (cli_t *cli) ;

void 
cli_screen_enable_timestamp (cli_t *cli);

void
cli_debug_print_stats (cli_t *cli) ;

bool
cli_is_buffer_empty (cli_t *cli);

void
cli_process_key_interrupt(int ch);

void
cli_screen_operational_mode_display (unsigned char *msg, int msg_size, bool display);

cli_history_t *
cli_get_default_history ();

void
cli_history_show () ;

void
cli_append_char (cli_t *default_cli, unsigned char ch, bool move_cursor) ;

void
cli_remove_trailing_char (cli_t *default_cli, bool move_cursor) ;

void 
cli_sanity_check (cli_t *cli) ;

bool 
cli_is_historical (cli_t *cli);

cmd_tree_cursor_t *
cli_get_cmd_tree_cursor (cli_t *cli) ;

 #endif