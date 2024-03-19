/*
 * =====================================================================================
 *
 *       Filename:  CmTreeCursor.cpp
 *
 *    Description:  This file Implements KeyProcessor Module
 *
 *        Version:  1.0
 *        Created:  Thursday 09 July 2023 05:37:07  IST
 *       Revision:  1.0
 *       Compiler:  gcc/g++
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(2012-2017)
 *                           Juniper Networks(2017-2021)
 *                           Cisco Systems(2021-2023)
 *                           CALIX(2023-Present)
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <ncurses.h>
#include <assert.h>
#include <stdbool.h>
#include <signal.h>
#include "../../stack/stack.h"
#include "../cli_const.h"
#include "cmdtlv.h"
#include "KeyProcessor.h"
#include "CmdTree/CmdTree.h"
#include "CmdTree/CmdTreeCursor.h"

#define ctrl(x)           ((x) & 0x1f)

typedef struct cli_ {

    unsigned char clibuff[MAX_COMMAND_LENGTH];
    int current_pos;
    int start_pos;
    int end_pos;
    int cnt;
    int row_store;
    int col_store;
    cmd_tree_cursor_t *cmdtc;
    struct cli_ *next;
    struct cli_ *prev;
} cli_t;

typedef struct cli_history_ {

    cli_t *first;
    cli_t *last;
    int count;  
    cli_t *curr_ptr;
} cli_history_t;

static cli_t *default_cli = NULL;
static cli_t *cli_store = NULL;
static cli_history_t *default_cli_history_list = NULL;
static bool keyp_char_mode = true;

bool 
cli_is_char_mode_on () {

    return keyp_char_mode ;
}

cli_history_t *
cli_get_default_history () {

    return default_cli_history_list ;
}

#define MODE_MSG_DISPLAY    \
    cli_screen_operational_mode_display ( \
                (unsigned char *) (cli_is_char_mode_on() ? "Char-Mode" : "Line-Mode"), 0, false)

static bool
key_processor_should_enter_line_mode (int key) {

    switch (key) {

        case KEY_HOME:
        case KEY_END:
        case KEY_LEFT:
        case KEY_RIGHT:
        case ctrl('n'):
        case ctrl('w'):
        case KEY_DC:
        case KEY_UP:
        case KEY_DOWN:
            return true;
    }

    /* If user attempt to edit the line in the history, enter to line mode immediately*/
    if (default_cli_history_list->curr_ptr) {

        switch (key) {

            case KEY_ENTER:
            case KEY_ASCII_NEWLINE:
                break;
            default:
                /* If we attempt to modify or work with the historical command, Immediately enter into line mode*/
                return true;
        }
    }
    return false;
}

/* Return 0 on success */
static int
cli_submit (cli_t *cli) {

    int ret = -1;
    bool parse_rc = true;

    if (cli_is_buffer_empty (cli)) return -1;

    if (cli_is_char_mode_on ()) {

        parse_rc = cmd_tree_process_carriage_return_key(cli->cmdtc);
        if (parse_rc) ret = 0;
    }
    else {
        cli->current_pos = cli->end_pos;
         cmdtc_parse_full_command(cli);
         ret = 0;
    }

    return ret;
}

static bool
cli_is_same (cli_t *cli1, cli_t *cli2) {

    if (memcmp(cli1->clibuff, cli2->clibuff, sizeof(cli2->clibuff)) == 0) {
        return true;
    }
    return false;
}

bool 
cli_is_historical (cli_t *cli) {
    
    return default_cli_history_list->curr_ptr == cli;
}

cmd_tree_cursor_t *
cli_get_cmd_tree_cursor (cli_t *cli)  {

    return cli->cmdtc;
}

void 
cli_set_cmd_tree_cursor (cli_t *cli, cmd_tree_cursor_t *cmdtc)  {

    assert (!cli->cmdtc);
    cli->cmdtc = cmdtc;
}

static const char *exceptional_cmds [] = { 
                                    "show history\0",
                                    "show help\0",
                                    NULL};

void 
cli_record_cli_history (cli_history_t *cli_history, cli_t *new_cli) {

    if (cli_is_buffer_empty (new_cli)) return;
    if (default_cli_history_list->curr_ptr == new_cli) return;
    
    int i = 0, size;
    while (exceptional_cmds[i]) {

        if (strncmp ((const char *)cli_get_user_command(new_cli, &size),
                             exceptional_cmds[i],
                             strlen (exceptional_cmds[i]))) {
            i++;
            continue;
        }
        
        free(new_cli);
        return;
    }

    cli_t *first_cli = cli_history->first;

    if (!first_cli) {
        cli_history->first = new_cli;
        cli_history->last = new_cli;
        cli_history->count++;
        return;
    }

    if (cli_is_same (new_cli, first_cli)) {
        free(new_cli);
        return;
    }

    if (cli_history->count ==  CLI_HISTORY_LIMIT) {
        
        cli_t *new_last = cli_history->last->prev;
        free(new_last->next);
        new_last->next = NULL;
        cli_history->last = new_last;
    }

    new_cli->next = first_cli;
    first_cli->prev = new_cli;
    cli_history->first = new_cli;
    cli_history->count++;
}

cli_t *
cli_malloc () {

    return (cli_t *)calloc (1, sizeof (cli_t));
}

extern void ut_parser_init ( ) ;

/* Fn ptr to store the application specific ctrl C handler*/
static void (*app_ctrlC_signal_handler)(void) = NULL;

/* Public API to allow application to register ctrlC handler*/
void
cli_register_ctrlC_handler(void (*fn_ptr)(void))
{
    app_ctrlC_signal_handler = fn_ptr;
}

extern int cprintf (const char* format, ...) ;
extern bool libcli_terminate_refresh ();
extern void init_filters () ;

static void
ctrlC_signal_handler(int sig)
{
    cprintf("Ctrl-C pressed\n");

    if (libcli_terminate_refresh ()) {
        return;
    }

    if (app_ctrlC_signal_handler)
    {   
        app_ctrlC_signal_handler();
    }   
    else
    {   
        cprintf("Bye Bye\n");
        exit(0);
    }   
}

void
libcli_init () {

    default_cli = (cli_t *)calloc (1, sizeof(cli_t));
    cli_set_hdr (default_cli, (unsigned char *)DEF_CLI_HDR, (uint8_t) strlen (DEF_CLI_HDR));
    cmd_tree_init ();
    default_cli->cmdtc = cmdtc_tree_get_cursor ();
    default_cli_history_list = (cli_history_t *)calloc (1, sizeof (cli_history_t));
    default_cli_history_list->curr_ptr = NULL;

    WINDOW *window = initscr();          // Initialize ncurses
    scrollok(window, TRUE);    // Enable scrolling for the window
    keypad(stdscr, TRUE); // Enable reading of function keys
    cbreak();         // Disable line buffering
    noecho();        // Disable character echoing
    refresh();        // Update the screen

    assert (has_colors() );
    start_color();
    init_pair(GRASS_PAIR, COLOR_YELLOW, COLOR_GREEN);
    init_pair(WATER_PAIR, COLOR_CYAN, COLOR_BLUE);
    init_pair(MOUNTAIN_PAIR, COLOR_BLACK, COLOR_WHITE);
    init_pair(PLAYER_PAIR, COLOR_RED, COLOR_MAGENTA);
    init_pair(RED_ON_BLACK, COLOR_RED, COLOR_BLACK);
    init_pair(GREEN_ON_BLACK, COLOR_GREEN, COLOR_BLACK);

    ut_parser_init ( ) ;
    signal(SIGINT, ctrlC_signal_handler);
    init_filters () ;
}

void
cli_content_reset (cli_t *cli) {

    memset (&cli->clibuff[cli->start_pos], 0, cli->end_pos - cli->start_pos);
    cli->current_pos = cli->start_pos;
    cli->end_pos = cli->start_pos;
    cli->cnt = cli->start_pos;
}

void 
cli_complete_reset (cli_t *cli) {

    cmd_tree_cursor_t *cmdtc = cli->cmdtc;
    cli_t *cli_prev = cli->prev;
    cli_t *cli_next = cli->next;

    memset (cli, 0, sizeof (cli_t));
    cli->cmdtc = cmdtc;
    cli->prev = cli_prev;
    cli->next = cli_next;
}

unsigned char *
cli_get_cli_buffer (cli_t *cli, int *size) {

    if (size) {
        *size = (cli->end_pos);
    }
    return cli->clibuff;
}

unsigned char *
cli_get_user_command (cli_t *cli, int *size) {

    unsigned char *cmd = &cli->clibuff[cli->start_pos];
    *size = cli->end_pos - cli->start_pos;
    return cmd;
}

int
cli_append_user_command (cli_t *cli, unsigned char *cmd, int size) {

    unsigned char *cmd1 = &cli->clibuff[cli->end_pos];
    memcpy (cmd1, cmd, size);
    cli->cnt += size;
    cli->end_pos += size;
    cli->current_pos = cli->end_pos;
    return cli->cnt;
}

void cli_printsc (cli_t *cli, bool next_line) {

    #if 0
    /* It dont scroll the screen up*/
    if (next_line) cli_screen_cursor_move_next_line ();
    #else
    if (next_line) printw("\n");
    #endif
    printw("%s", cli->clibuff);
}

void
cli_debug_print_stats (cli_t *cli) {

    //printw("\n%s", cli->clibuff);
    printw ("\ncurr pos =  %d, start pos = %d, end_pos = %d, cnt = %d", 
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

bool 
cli_is_prev_char (cli_t *cli, unsigned char ch) {

    return (cli->clibuff[cli->current_pos -1] == ch);
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

    int row, col;
    getyx(stdscr, row, col);
    move (row, col + cols);
}

void 
cli_set_hdr (cli_t *cli, unsigned char *new_hdr, uint8_t size) {

    if (new_hdr) {
        cli_complete_reset (cli);
        memcpy (cli->clibuff , new_hdr, size);
    }
    cli->start_pos = size;
    cli->current_pos = cli->start_pos;
    cli->end_pos = cli->start_pos;
    cli->cnt = size;
}

bool
cli_cursor_is_at_end_of_line (cli_t *cli) {

    return (cli->current_pos == cli->end_pos);
}

bool
cli_cursor_is_at_begin_of_line (cli_t *cli) {

    return (cli->current_pos == cli->start_pos);
}

void 
cli_content_shift_right (cli_t *cli) {

    int i;

   if ( cli->cnt == MAX_COMMAND_LENGTH || cli_is_buffer_empty(cli)) return;

    for (i = cli->end_pos; i >= cli->current_pos; i--) {
        cli->clibuff[i+1] = cli->clibuff[i];
    }

    cli->cnt++;
    cli->end_pos++;
}

void 
cli_content_shift_left (cli_t *cli) {

    int i;

   if (cli_is_buffer_empty(cli)) return;

    for (i = cli->current_pos; i < cli->end_pos; i++) {
        cli->clibuff[i] = cli->clibuff[i+1];
    }

    cli->clibuff[cli->end_pos -1] = '\0';
    cli->cnt--;
    cli->end_pos--;
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

void
cli_screen_operational_mode_display (unsigned char *msg, int msg_size, bool display) {

    int row, col;
    getyx(stdscr, row, col);
    move (0, 0);
    printw ("%s", msg);
    move(row, col);
}

void
cli_process_key_interrupt(int ch)
{
    int i, bs_count;
    cmdt_cursor_op_res_t rc;

    switch (ch)
    {
    case ctrl('t'): // goto apex
        /* Come out of history browsing*/
        if (cli_store) {
            default_cli = cli_store;
            cli_store = NULL;
            default_cli_history_list->curr_ptr = NULL;
        }
        cli_complete_reset(default_cli);
        if (cmdtc_am_i_working_in_mode(default_cli->cmdtc)) {
            cmd_tree_uninstall_universal_params(cmdtc_get_root (default_cli->cmdtc));
        }
        cmd_tree_cursor_deinit (default_cli->cmdtc);
        cli_set_hdr (default_cli, (unsigned char *)DEF_CLI_HDR, strlen (DEF_CLI_HDR));
        cli_screen_cursor_reset_current_line();
        cli_printsc (default_cli, false);
        /* Come out of line-mode if working in that mode*/
        keyp_char_mode = true;
        MODE_MSG_DISPLAY;        
        break;
    case ctrl('n'):
        if (cli_cursor_is_at_end_of_line(default_cli))
            break;
        cli_screen_cursor_save_screen_pos(default_cli);
        for (i = default_cli->current_pos; i <= default_cli->end_pos; i++)
        {
            default_cli->clibuff[i] = '\0';
            printw(" ");
        }
        default_cli->cnt -= default_cli->end_pos - default_cli->current_pos;
        default_cli->end_pos = default_cli->current_pos;
        move(default_cli->row_store, default_cli->col_store);
        break;
    case ctrl('l'):
        clear();
        cli_printsc(default_cli, true);
        MODE_MSG_DISPLAY;
        break;
    case KEY_HOME: /* Inbuilt , provided by ncurses */
        if (cli_cursor_is_at_begin_of_line(default_cli))
            break;
        cli_screen_cursor_move_cursor_left(
            default_cli->current_pos - default_cli->start_pos, false);
        default_cli->current_pos = default_cli->start_pos;
        break;
    case KEY_END:
        cli_screen_cursor_move_cursor_right(default_cli->end_pos - default_cli->current_pos);
        default_cli->current_pos = default_cli->end_pos;
        break;
    case KEY_PPAGE: /* Page UP*/
    case ctrl(']'):
        if (!cli_cursor_is_at_begin_of_line (default_cli)) break;
        if (!cli_is_char_mode_on ()) break;
        bs_count = cmdtc_process_pageup_event (default_cli->cmdtc);
        i = bs_count; 
        if (bs_count) {
            while (bs_count--) {
                cli_remove_trailing_char (default_cli , true);
            }
        }
        if (i == 0) break; /* We are already at the apex root */
        /* This page up event has caused us to reach apex root level, We just need
            to print one space only, find through exp, dont think too much !! */
        if (cmdtc_is_cursor_at_apex_root (default_cli->cmdtc)) {
            cli_append_char (default_cli, ' ', true);
            default_cli->start_pos += 1;
            break;
        }
        cli_append_char (default_cli, '>', false);
        printw(">");
        cli_append_char (default_cli, ' ', false);
        printw(" ");
        default_cli->start_pos += 2;
        break;    
    case KEY_NPAGE: /* Page Down, used for debugging purpose*/
        cli_debug_print_stats (default_cli);
        cmdtc_debug_print_stats(default_cli->cmdtc);
        break;
    /* Need to be careful with Backspace key as its ascii code varies on different systems*/
    case KEY_BACKSPACE:  /*On Linux Platform, BS has ascii code of 263*/
    case KEY_BACKSPACE_MOBAXTERM: /* On Windows, BS has ascii code of 8*/
        /* Case 1 : if we are at the beginning of line */
        if (cli_cursor_is_at_begin_of_line (default_cli)) break;

        if (cli_is_char_mode_on ()) {

            /* in Char mode we are always at the end of line*/
            assert(cli_cursor_is_at_end_of_line (default_cli));

            if (cmd_tree_cursor_move_one_char_back (default_cli->cmdtc)) {

                cli_screen_cursor_move_cursor_left (1, true);
                default_cli->clibuff[--default_cli->end_pos] = '\0';
                default_cli->cnt--;
                default_cli->current_pos--;
                break;
            }

            bs_count = cmd_tree_cursor_move_one_level_up (default_cli->cmdtc, true, false);
            if (bs_count) {
                cli_screen_cursor_move_cursor_left (bs_count, true);
                while (bs_count--) {
                    default_cli->clibuff[--default_cli->end_pos] = '\0';
                    default_cli->cnt--;
                    default_cli->current_pos--;
                }
            }
            break;
        }

        /* If we are in line mode */
        /* Case 2 : if we are at the end of line*/
        else if (cli_cursor_is_at_end_of_line (default_cli))
        {
            #if 0
            cli_remove_trailing_char(default_cli, true);
            #else
            default_cli->current_pos--;
            default_cli->end_pos--;
            default_cli->cnt--;
            default_cli->clibuff[default_cli->current_pos] = '\0';
            cli_screen_cursor_move_cursor_left(1, true);
            #endif
        }

        /* Case 3 : we are in the middle of the line */
        else
        {
            default_cli->current_pos--;
            cli_content_shift_left(default_cli);
            cli_screen_cursor_move_cursor_left(1, true);
            cli_screen_cursor_save_screen_pos(default_cli);
            for (i = default_cli->current_pos; i < default_cli->end_pos; i++)
            {
                printw("%c", default_cli->clibuff[i]);
            }
            printw(" ");
            move(default_cli->row_store, default_cli->col_store);
            default_cli->current_pos = default_cli->col_store;
        }
        break;
    case KEY_DC: /* delete key is pressed */
        /* Case 1 : if we are at the beginning or middle of the line */
        if (!cli_cursor_is_at_end_of_line (default_cli))
        {

            cli_content_shift_left(default_cli);
            cli_screen_cursor_save_screen_pos(default_cli);
            for (i = default_cli->current_pos; i < default_cli->end_pos; i++)
            {
                printw("%c", default_cli->clibuff[i]);
            }
            printw(" ");
            move(default_cli->row_store, default_cli->col_store);
            default_cli->current_pos = default_cli->col_store;
        }

        /* Case 2 : if we are at the end of line*/
        else if (cli_cursor_is_at_end_of_line (default_cli))
        {
            break;
        }
        break;
    case KEY_ASCII_NEWLINE:
    case KEY_ENTER:
       
        if (default_cli_history_list->curr_ptr == NULL)
        {
            cli_screen_cursor_save_screen_pos(default_cli);
            move(default_cli->row_store, default_cli->end_pos);
            cli_submit(default_cli);
            cli_content_reset(default_cli);
            cli_printsc(default_cli, true);
        }
        else
        {
            /* CLI is being picked up from history. Historical CLIs do
                not have cmdtc*/
            cli_screen_cursor_save_screen_pos(default_cli);
            move(default_cli->row_store, default_cli->end_pos);
            assert(!default_cli->cmdtc);
            cli_submit(default_cli);
            assert(cli_store);
            default_cli = cli_store;
            cli_store = NULL;
            cli_content_reset(default_cli);
            cli_printsc(default_cli, true);
            default_cli_history_list->curr_ptr = NULL;
        }
        keyp_char_mode = true;
        MODE_MSG_DISPLAY;
        assert(default_cli->cmdtc);
        break;
    case KEY_RIGHT:
        if (cli_cursor_is_at_end_of_line (default_cli))
            break;
        cli_screen_cursor_move_cursor_right(1);
        default_cli->current_pos++;
        break;
    case KEY_LEFT:
         if (cli_cursor_is_at_begin_of_line (default_cli))
            break;
        cli_screen_cursor_move_cursor_left (1, false);
        default_cli->current_pos--;
        break;
    case KEY_UP:
        cli_screen_cursor_save_screen_pos(default_cli);
        if (default_cli_history_list->curr_ptr == NULL)
        {
            default_cli_history_list->curr_ptr = default_cli_history_list->first;
        }
        else
        {
            /* We have hit the ceiling in the history, block the user
                KEY UP strokes now*/
            if (!default_cli_history_list->curr_ptr->next) {
                break;
            }
            default_cli_history_list->curr_ptr =
                default_cli_history_list->curr_ptr->next;
        }
        if (default_cli_history_list->curr_ptr == NULL)
            break;
        deleteln();
        move(default_cli->row_store, 0);
        cli_printsc(default_cli_history_list->curr_ptr, false);
        if (!cli_store)
            cli_store = default_cli;
        default_cli = default_cli_history_list->curr_ptr;
        break;
    case KEY_DOWN:
        cli_screen_cursor_save_screen_pos(default_cli);
        if (default_cli_history_list->curr_ptr == NULL) {
            break;
        }
        else
        {
            default_cli_history_list->curr_ptr =
                default_cli_history_list->curr_ptr->prev;
        }
        if (default_cli_history_list->curr_ptr == NULL) {
            /* Load the current default cli that was being typed by the user*/
            default_cli = cli_store;
            cli_store = NULL;
            deleteln();
            move(default_cli->row_store, 0);
            cli_printsc(default_cli, false);
            move(default_cli->row_store, default_cli->current_pos);
            break;
        }
        deleteln();
        move(default_cli->row_store, 0);
        cli_printsc(default_cli_history_list->curr_ptr, false);
        if (!cli_store)
            cli_store = default_cli;
        default_cli = default_cli_history_list->curr_ptr;
        break;
    case KEY_ASCII_TAB:
    case KEY_ASCII_SPACE:
        rc = cmdt_cursor_parse_next_char(default_cli->cmdtc, ch);
        switch (rc) {
            case cmdt_cursor_ok:
                /* print the blank character, take care that we might be typing not in the end*/
                /* This code will be returned when the user has pressed ' ' after typing out the
                    value of a leaf in cli*/
                   if (cli_cursor_is_at_end_of_line(default_cli)) {
                    #if 0
                        cli_append_char (default_cli, KEY_ASCII_SPACE, true);
                    #else
                        default_cli->clibuff[default_cli->current_pos++] = (char)KEY_ASCII_SPACE;
                        default_cli->end_pos++;
                        default_cli->cnt++;
                        printw(" ");
                    #endif
                   }
                   else {
                        cli_content_shift_right(default_cli);
                        default_cli->clibuff[default_cli->current_pos++] = (char)KEY_ASCII_SPACE;
                        cli_screen_cursor_save_screen_pos(default_cli);
                        for (i = default_cli->current_pos - 1; i < default_cli->end_pos; i++) {
                            printw("%c", default_cli->clibuff[i]);
                        }
                        move(default_cli->row_store, default_cli->current_pos);
                   }
                break;
            case cmdt_cursor_done_auto_completion:
                /* print the blank character, take care that we might be typing not in the end*/
                    if (cli_cursor_is_at_end_of_line(default_cli)) {
                    #if 0
                        cli_append_char (default_cli, KEY_ASCII_SPACE, true);
                    #else 
                        default_cli->clibuff[default_cli->current_pos++] = (char)KEY_ASCII_SPACE;
                        default_cli->end_pos++;
                        default_cli->cnt++;
                        printw(" ");
                    #endif
                   }
                   else {
                        cli_content_shift_right(default_cli);
                        default_cli->clibuff[default_cli->current_pos++] = (char)KEY_ASCII_SPACE;
                        cli_screen_cursor_save_screen_pos(default_cli);
                        for (i = default_cli->current_pos - 1; i < default_cli->end_pos; i++) {
                            printw("%c", default_cli->clibuff[i]);
                        }
                        move(default_cli->row_store, default_cli->current_pos);
                   }
                break;
                break;
            case cmdt_cursor_no_match_further:
                break;
        }
        break;
    /* Put all the probable fall-through to default cases here*/
    case SUBOPTIONS_CHARACTER:
            if (cli_is_char_mode_on() &&
                 cli_is_prev_char (default_cli, ' ')) {
                cmdtc_process_question_mark (default_cli->cmdtc);
                break;
            }
    case MODE_CHARACTER:
            if (cli_is_char_mode_on() &&
                cli_is_prev_char (default_cli, ' ')) {
                cmd_tree_enter_mode (default_cli->cmdtc);
                break;
            }
    case CMD_EXPANSION_CHARACTER:
            if (cli_is_char_mode_on() &&
                     cli_is_prev_char (default_cli, ' ')) {
                printw("\n");
                cmdtc_display_all_complete_commands (default_cli->cmdtc);
                cli_printsc (default_cli, true);
                break;
            }
    default:
        if (default_cli->cnt == MAX_COMMAND_LENGTH)
            break;
        if (cli_cursor_is_at_end_of_line(default_cli))
        {
            rc = cmdt_cursor_parse_next_char(default_cli->cmdtc, ch);
            switch (rc)
            {
            case cmdt_cursor_ok:
            #if 0
                cli_append_char (default_cli, ch, false);
            #else
                default_cli->clibuff[default_cli->current_pos++] = (char)ch;
                default_cli->end_pos++;
                default_cli->cnt++;
            #endif
                printw("%c", ch);
                break;
            case cmdt_cursor_no_match_further:
                break;
            }
        }
        else
        {
            /* User is typing in the middle OR beginning of the line*/
            rc = cmdt_cursor_parse_next_char(default_cli->cmdtc, ch);
            switch (rc)
            {
            case cmdt_cursor_ok:
                cli_content_shift_right(default_cli);
                default_cli->clibuff[default_cli->current_pos++] = (char)ch;
                cli_screen_cursor_save_screen_pos(default_cli);
                for (i = default_cli->current_pos - 1; i < default_cli->end_pos; i++)
                {
                    printw("%c", default_cli->clibuff[i]);
                }
                move(default_cli->row_store, default_cli->current_pos);
                break;
            case cmdt_cursor_no_match_further:
                break;
            }
        }
        break;
    }
}

void 
cli_start_shell ();

void 
cli_start_shell () {

    int ch;  

    cli_printsc (default_cli, true);
    MODE_MSG_DISPLAY;

    while (true) {
    
        ch = getch();

        if (default_cli->cnt == MAX_COMMAND_LENGTH) continue;

        if (cli_is_char_mode_on()) {



            if ( key_processor_should_enter_line_mode (ch)) {
                keyp_char_mode = false;
                /* Reset the cmd tree cbc cursor to be used for next command now afresh*/
                cmd_tree_cursor_reset_for_nxt_cmd (default_cli->cmdtc);
                MODE_MSG_DISPLAY;
            }
        }

        cli_process_key_interrupt ((int)ch);
    }
}

void
cli_append_char (cli_t *default_cli, unsigned char ch, bool move_cursor)  {

    assert (cli_cursor_is_at_end_of_line(default_cli));
    assert (default_cli->current_pos >= default_cli->start_pos);
    default_cli->clibuff[default_cli->current_pos++] = ch;
    default_cli->cnt++;
    default_cli->end_pos++;
    if (move_cursor) {
        cli_screen_cursor_move_cursor_right (1);
    }
}

void
cli_remove_trailing_char (cli_t *default_cli, bool move_cursor) {

    assert (cli_cursor_is_at_end_of_line(default_cli));
    assert (default_cli->current_pos >= default_cli->start_pos);
    default_cli->clibuff[--default_cli->end_pos] = '\0';
    default_cli->cnt--;
    default_cli->current_pos--;
    if (default_cli->end_pos < default_cli->start_pos) default_cli->start_pos--;
    if (move_cursor) {
        cli_screen_cursor_move_cursor_left  (1, true);
    }
}

void 
cli_sanity_check (cli_t *cli) {

    assert (cli->current_pos == cli->end_pos);
    assert (cli->cnt == cli->end_pos);
}

void
cli_history_show () {

    cli_t *cli = default_cli_history_list->first;

    while (cli) {
        printw ("\n%s", cli->clibuff);
        cli = cli->next;
    }
}

