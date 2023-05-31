#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <ncurses.h>
#include <assert.h>

#include "cli_const.h"
#include "KeyProcessor.h"

#define ctrl(x)           ((x) & 0x1f)

typedef struct cli_ {

    unsigned char clibuff[MAX_COMMAND_LENGTH];
    int current_pos;
    int start_pos;
    int end_pos;
    int cnt;
    int row_store;
    int col_store;
    struct cli_ *next;
    struct cli_ *prev;
} cli_t;

typedef struct cli_history_ {

    cli_t *cli_history_list;
    int count;
    cli_t *curr_ptr;
} cli_history_t;

static cli_t *default_cli = NULL;
static cli_t *cli_store = NULL;
static cli_history_t *default_cli_history_list = NULL;
cli_command_parser_cbk cli_command_parser = NULL;

static int
cli_application_process (cli_t *cli) {

    if (cli_is_buffer_empty (cli)) return -1;
    return cli_command_parser (&cli->clibuff[cli->start_pos], cli->end_pos - cli->start_pos);
}

static bool
cli_is_same (cli_t *cli1, cli_t *cli2) {

    if (memcmp(cli1->clibuff, cli2->clibuff, sizeof(cli2->clibuff)) == 0) {
        return true;
    }
    return false;
}

void 
cli_record_copy (cli_history_t *cli_history, cli_t *new_cli) {

    if (cli_history->count ==  CLI_HISTORY_LIMIT) return;
    if (new_cli->cnt== 0) return;

    cli_t *cli = (cli_t *)calloc (1, sizeof (cli_t));
    memcpy (cli, new_cli, sizeof (cli_t));

    if (cli_history->cli_history_list == NULL) {
        cli_history->cli_history_list = cli;
        cli_history->count++;
        return;
    }

    cli_t *first_cli = cli_history->cli_history_list;

    if (cli_is_same (cli, first_cli)) {
        free(cli);
        return;
    }

    cli->next = first_cli;
    first_cli->prev = cli;
    cli_history->cli_history_list = cli;
}

void
cli_key_processor_init (cli_t **cli, cli_command_parser_cbk command_parser) {

    assert(!default_cli);
    assert(!(*cli));
    assert (!cli_command_parser);

    *cli = (cli_t *)calloc (1, sizeof(cli_t));
    default_cli = *cli;

    cli_set_hdr (default_cli, (unsigned char *)DEF_CLI_HDR, (uint8_t) strlen (DEF_CLI_HDR));

    default_cli_history_list = (cli_history_t *)calloc (1, sizeof (cli_history_t));
    default_cli_history_list->curr_ptr = NULL;

    cli_command_parser = command_parser;

    WINDOW *window = initscr();          // Initialize ncurses
    scrollok(window, TRUE);    // Enable scrolling for the window
    keypad(stdscr, TRUE); // Enable reading of function keys
    cbreak();         // Disable line buffering
    noecho();        // Disable character echoing
    refresh();        // Update the screen
}

void
cli_key_processor_cleanup () {

    cli_t *cli;

    free(default_cli);

    default_cli = NULL;

    while ((cli = default_cli_history_list->cli_history_list)) {

        default_cli_history_list->cli_history_list = cli->next;
        free(cli);
    }
    free( default_cli_history_list);
    default_cli_history_list = NULL;
    endwin();
}

void
cli_content_reset (cli_t *cli) {


    cli_t *cli2 = cli ? cli : default_cli;
    memset (&cli2->clibuff[cli2->start_pos], 0, cli2->end_pos - cli2->start_pos);
    cli2->current_pos = cli2->start_pos;
    cli2->end_pos = cli2->start_pos;
    cli2->cnt = cli2->start_pos;
}

void cli_printsc (cli_t *cli, bool next_line) {

    cli_t *cli2 = cli ? cli : default_cli;
    if (next_line) printw ("\n");
    printw("%s", cli2->clibuff);
}

void
cli_debug_print_stats (cli_t *cli) {

    printw("\n%s", cli->clibuff);
    printw ("\ncurr pos =  %d, start pos = %d, end_pos = %d, cnt = %d\n", 
        cli->current_pos, cli->start_pos, cli->end_pos, cli->cnt);
}

bool
cli_is_buffer_empty (cli_t *cli) {

    return (cli->cnt == cli->start_pos);
}

cli_t * 
cli_get_default_cli () {

    return default_cli;
}

void 
cli_set_default_cli (cli_t *cli) {

    default_cli = cli;
}

void 
cli_screen_cursor_move_cursor_left (int cols, bool remove_char) {

    int i;
    int row, col;
    getyx(stdscr, row, col);
    move (row, col - cols);
    if (remove_char) {
    for (i = 0; i < cols; i++) printw(" ");
        move (row, col - cols);
    }
}

void 
cli_screen_cursor_move_cursor_right (int cols) {

    int i;
    int row, col;
    getyx(stdscr, row, col);
    move (row, col + cols);
}

void 
cli_set_hdr (cli_t *cli, unsigned char *new_hdr, uint8_t size) {

    cli_t *cli2 = cli ? cli : default_cli;
    memset (cli2, 0, sizeof (cli_t));
    memcpy (cli2->clibuff , new_hdr, size);
    cli2->start_pos = size;
    cli2->current_pos = cli2->start_pos;
    cli2->end_pos = cli2->start_pos;
    cli2->cnt = size;
}

bool
cli_cursor_is_at_end_of_line (cli_t *cli) {

    cli_t *cli2 = cli ? cli : default_cli;

    return (cli2->current_pos == cli2->end_pos);
}

bool
cli_cursor_is_at_begin_of_line (cli_t *cli) {

    cli_t *cli2 = cli ? cli : default_cli;

    return (cli2->current_pos == cli2->start_pos);
}

void 
cli_content_shift_right (cli_t *cli) {

    int i;

    cli_t *cli2 = cli ? cli : default_cli;

   if ( cli2->cnt == MAX_COMMAND_LENGTH || cli2->cnt == 0) return;

    for (i = cli2->end_pos; i >= cli2->current_pos; i--) {
        cli2->clibuff[i+1] = cli2->clibuff[i];
    }

    cli2->cnt++;
    cli2->end_pos++;
}

void 
cli_content_shift_left (cli_t *cli) {

    int i;

    cli_t *cli2 = cli ? cli : default_cli;

   if (  cli2->cnt == 0) return;

    for (i = cli2->current_pos; i < cli2->end_pos; i++) {
        cli2->clibuff[i] = cli2->clibuff[i+1];
    }

    cli2->clibuff[cli2->end_pos -1] = '\0';
    cli2->cnt--;
    cli2->end_pos--;
}

void
cli_screen_cursor_reset_current_line () {

    int row, col;
    getyx(stdscr, row, col);
    deleteln();
    move (row, 0);
}

void
cli_screen_cursor_move_next_line () {

    int row, col;
    getyx(stdscr, row, col);
    move (row + 1, 0);
}

void
cli_screen_cursor_save_screen_pos (cli_t *cli) {

    int row, col;
    getyx(stdscr, row, col);
    cli->row_store = row;
    cli->col_store = col;
}

void 
cli_screen_enable_timestamp (cli_t *cli) {

}


/// @brief  Fn to parse the user terminal input

void 
cli_start_shell () {

    int ch;
    int i;
    cli_printsc (NULL, true);

    while (true) {

        ch = getch();

         switch (ch) {
            case ctrl('n'):
                if (cli_cursor_is_at_end_of_line (default_cli)) break;
                cli_screen_cursor_save_screen_pos (default_cli);
                for (i = default_cli->current_pos; i <= default_cli->end_pos; i++) {
                    default_cli->clibuff[i] = '\0';
                    printw(" ");
                }
                default_cli->cnt -= default_cli->end_pos - default_cli->current_pos;
                default_cli->end_pos = default_cli->current_pos;
                move (default_cli->row_store, default_cli->col_store);
                break;
            case ctrl('w'):
                /* ToDo : Delete the current Word */
                break;
            case ctrl('l'):
                clear();
                cli_printsc (default_cli, true);
                break;
            case KEY_HOME: /* Inbuilt , provided by ncurses */
                if (cli_cursor_is_at_begin_of_line(default_cli)) break;
                cli_screen_cursor_move_cursor_left (
                        default_cli->current_pos - default_cli->start_pos, false);
                default_cli->current_pos = default_cli->start_pos;
                break;
            case KEY_END:
                cli_screen_cursor_move_cursor_right 
                    (default_cli->end_pos - default_cli->current_pos);
                default_cli->current_pos = default_cli->end_pos;
                break;
            case KEY_BACKSPACE:
                /* Case 1 : if we are at the beginning of line */
                if (default_cli->current_pos == default_cli->start_pos) break;

                /* Case 2 : if we are at the end of line*/
                else if (default_cli->current_pos == default_cli->end_pos) {
                    default_cli->current_pos--;
                    default_cli->end_pos--;
                    default_cli->cnt--;
                    default_cli->clibuff[default_cli->current_pos]= '\0';
                    cli_screen_cursor_move_cursor_left (1, true);
                }

                /* Case 3 : we are in the middle of the line */
                else {
                    default_cli->current_pos--;
                    cli_content_shift_left (default_cli);
                    cli_screen_cursor_move_cursor_left(1, true);
                    cli_screen_cursor_save_screen_pos(default_cli);
                    for (i = default_cli->current_pos; i < default_cli->end_pos; i++) {
                        printw ("%c", default_cli->clibuff[i]);
                    }
                    printw(" ");
                    move (default_cli->row_store, default_cli->col_store);
                    default_cli->current_pos = default_cli->col_store;
                }
                break;
            case KEY_DC: /* delete key is pressed */
                /* Case 1 : if we are at the beginning or middle of the line */
                if (default_cli->current_pos != default_cli->end_pos) {
                    
                    cli_content_shift_left (default_cli);
                    cli_screen_cursor_save_screen_pos(default_cli);
                    for (i = default_cli->current_pos; i < default_cli->end_pos; i++) {
                        printw ("%c", default_cli->clibuff[i]);
                    }
                    printw(" ");
                    move (default_cli->row_store, default_cli->col_store);
                    default_cli->current_pos = default_cli->col_store;
                }

                /* Case 2 : if we are at the end of line*/
                else if (default_cli->current_pos == default_cli->end_pos) {
                    break;
                }
                break;
            case KEY_ASCII_NEWLINE:
            case KEY_ENTER:
            if (default_cli_history_list->curr_ptr == NULL) {
                if (!cli_application_process(default_cli)) {
                    cli_record_copy(default_cli_history_list, default_cli);
                }
                cli_content_reset (default_cli);
                cli_printsc (default_cli, true);
            }
            else {
                 cli_application_process(default_cli);
                 assert(cli_store);
                 default_cli = cli_store;
                 cli_store = NULL;
                 cli_content_reset (default_cli);
                 cli_printsc (default_cli, true);
                 default_cli_history_list->curr_ptr = NULL;
            }
                break;
            case KEY_ASCII_TAB:
                cli_debug_print_stats(default_cli);
                break;
            case KEY_RIGHT:
                if (default_cli->current_pos == default_cli->end_pos) break;
                cli_screen_cursor_move_cursor_right(1);
                default_cli->current_pos++;
                break;
            case KEY_LEFT:
                if (default_cli->current_pos == default_cli->start_pos) break;
                cli_screen_cursor_move_cursor_left (1, false);
                default_cli->current_pos--;
                break;
            case KEY_UP:
                cli_screen_cursor_save_screen_pos (default_cli);
                if (default_cli_history_list->curr_ptr == NULL) {
                    default_cli_history_list->curr_ptr = default_cli_history_list->cli_history_list;
                }
                else {
                    default_cli_history_list->curr_ptr =
                        default_cli_history_list->curr_ptr->next;
                }
                 if (default_cli_history_list->curr_ptr == NULL) break;
                 deleteln();
                 move (default_cli->row_store, 0);
                 cli_printsc (default_cli_history_list->curr_ptr, false);
                 if (!cli_store) cli_store = default_cli;
                 default_cli = default_cli_history_list->curr_ptr;
                break;
            case KEY_DOWN:
                cli_screen_cursor_save_screen_pos (default_cli);
                if (default_cli_history_list->curr_ptr == NULL) {
                    break;
                }
                else {
                    default_cli_history_list->curr_ptr =
                        default_cli_history_list->curr_ptr->prev;
                }
                 if (default_cli_history_list->curr_ptr == NULL) break;
                 deleteln();
                 move (default_cli->row_store, 0);
                 cli_printsc (default_cli_history_list->curr_ptr, false);
                 if (!cli_store) cli_store = default_cli;
                 default_cli = default_cli_history_list->curr_ptr;
                break;
            default :
                if ( default_cli->cnt == MAX_COMMAND_LENGTH) break;
                if (cli_cursor_is_at_end_of_line (NULL)) {
                    default_cli->clibuff[default_cli->current_pos++] = (char)ch;
                    default_cli->end_pos++;
                    default_cli->cnt++;
                    printw("%c", ch);
                }
                else {
                    /* User is typing in the middle OR beginning of the line*/
                    cli_content_shift_right (NULL);
                    default_cli->clibuff[default_cli->current_pos++] = (char)ch;
                    cli_screen_cursor_save_screen_pos(default_cli);
                    for (i = default_cli->current_pos -1; i < default_cli->end_pos; i++) {
                        printw("%c", default_cli->clibuff[i]);
                    }
                    move(default_cli->row_store, default_cli->current_pos);
                }
                break;
        }
    }

   cli_key_processor_cleanup () ;
}
