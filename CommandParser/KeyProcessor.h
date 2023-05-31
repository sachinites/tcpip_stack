#ifndef __KEY_PROCESSOR__
#define __KEY_PROCESSOR__

#include  <stdbool.h>
#include <stdint.h>

typedef struct cli_ cli_t;
typedef struct cli_history_ cli_history_t;
typedef int (*cli_command_parser_cbk) (unsigned char *, int);

void cli_key_processor_init (cli_t **, cli_command_parser_cbk) ;

void cli_key_processor_cleanup ();

void cli_content_reset (cli_t *cli);

void cli_printsc (cli_t *cli, bool next_line) ;

void  cli_start_shell() ;

cli_t * cli_get_default_cli () ;

void cli_set_default_cli (cli_t *cli) ;

void cli_set_hdr (cli_t *cli, unsigned char *new_hdr, uint8_t size);

bool
cli_cursor_is_at_end_of_line (cli_t *cli);

bool
cli_cursor_is_at_begin_of_line (cli_t *cli);

void 
cli_content_shift_right (cli_t *cli);

void 
cli_content_shift_left (cli_t *cli);

void 
cli_record_copy (cli_history_t *cli_history, cli_t *new_cli);

void
cli_screen_cusor_reset_current_line ();

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

#endif