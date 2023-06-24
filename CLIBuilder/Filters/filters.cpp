/*
 * =====================================================================================
 *
 *       Filename:  filters.cpp
 *
 *    Description:  This file Implements Filters for CLIBuilder Library
 *
 *        Version:  1.0
 *        Created:  Thursday 15 June 2023 05:37:07  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(2012-2016)
 *                          Juniper Networks(2017-2021)
 *                          Cisco Systems(2021-2023)
 *                          CALIX(2023-Present)
 *
 * =====================================================================================
 */

#include <cstdarg>
#include <cstring>
#include <stdint.h>
#include <errno.h>
#include <mqueue.h>
#include "../cmdtlv.h"

#define OBUFFER_SIZE  256
#define CUM_BUFFER_MAX_SIZE 4096 /* must match with MAX_MSG_SIZE*/

static tlv_struct_t **filter_array = NULL;
static int filter_array_size = 0;
static unsigned char Obuffer[OBUFFER_SIZE] = {0};
static unsigned char Cumbuffer[CUM_BUFFER_MAX_SIZE] = {0};
static uint16_t cum_buffer_byte_cnt = 0;
static int count_lines = 0;
static bool count_filter_present = false;
static bool save_filter_present = false;
static bool first_line = false;

extern bool TC_RUNNING ;
extern int UT_PARSER_MSG_Q_FD; 

static bool
filter_inclusion (unsigned char *buffer, int size, unsigned char *pattern, int pattern_size) {

    return pattern_match ((char *)buffer, size, (char *)pattern);
}

static bool
filter_exclusion (unsigned char *buffer, int size, unsigned char *pattern, int pattern_size) {

    return !pattern_match ((char *)buffer, size, (char *)pattern);
}

void 
SetFilterContext (tlv_struct_t **lfilter_array, int lsize) {

    filter_array = lfilter_array;
    filter_array_size = lsize;
}

void 
UnsetFilterContext () {

    if (count_filter_present) {
        if (!TC_RUNNING) {
            printw ("\nlines : %d", count_lines);
        }
        else {
            cum_buffer_byte_cnt +=  sprintf((char *)Cumbuffer + cum_buffer_byte_cnt, "lines : %d\n", count_lines);
        }
    }

    filter_array = NULL;
    filter_array_size = 0;
    count_lines = 0;
    count_filter_present = false;
    save_filter_present = false;
    first_line = false;

    if (TC_RUNNING) {

        /* The show output of the command has come to an end , push all the show output data to
            the TC infra for further parsing and analysis*/
        if (mq_send (UT_PARSER_MSG_Q_FD, (char *)Cumbuffer, cum_buffer_byte_cnt + 1, 0) == -1 ) {
            printw ("mq_send failed on FD %d, errno = %d\n", UT_PARSER_MSG_Q_FD, errno);
        }

        /* Reset the Cum buffer for the next show command */
        memset (Cumbuffer, 0, cum_buffer_byte_cnt);
        cum_buffer_byte_cnt = 0;
    }

}

static void 
render_line (unsigned char *Obuffer, int msg_len) {

    if (!TC_RUNNING && !first_line) {

        printw("\n");
        first_line = true;
    }

    if (!TC_RUNNING) {
        printw("%s", Obuffer);
        return;
    }

    /* If the Test case is running, then collect individual printf statements in a Cumbuffer
        until all the show o/p of the command is collected. */
    memcpy (Cumbuffer +  cum_buffer_byte_cnt, Obuffer,  msg_len);
    cum_buffer_byte_cnt += msg_len;
}

/* override glibc printf */
int cprintf (const char* format, ...) {

    int i;
    va_list args;
    int msg_len;
    tlv_struct_t *tlv;
    bool patt_rc = false;
    bool inc_exc_pattern_present = false;

    va_start(args, format);
    memset (Obuffer, 0, OBUFFER_SIZE);
    vsnprintf((char *)Obuffer, OBUFFER_SIZE, format, args);
    msg_len = strlen ((const char *)Obuffer);

    va_end(args);

    if (filter_array_size == 0) {

         render_line (Obuffer, msg_len);
         return 0;
    }

    for (i = 0; i < filter_array_size; i++) {
        
        tlv = filter_array[i];
        if (strcmp ((const char *)tlv->leaf_id, "incl-pattern") == 0) {

             inc_exc_pattern_present = true;

            patt_rc = filter_inclusion (Obuffer, msg_len, 
                                                (unsigned char *)tlv->value, 
                                                strlen ((const char *)tlv->value));
            if (!patt_rc) return 0;
        }
        else if (strcmp ((const char *)tlv->leaf_id, "excl-pattern") == 0) {

             inc_exc_pattern_present = true;

            patt_rc = filter_exclusion (Obuffer, msg_len, 
                                                (unsigned char *)tlv->value, 
                                                strlen ((const char *)tlv->value));

            if (!patt_rc) return 0;
        }
        else if (strcmp ((const char *)tlv->value, "count") == 0) {
            
            count_filter_present  = true;

            if (inc_exc_pattern_present) {
                if (patt_rc) count_lines++;
            }
            else {
                count_lines++;
            }
        }
        else if (strcmp ((const char *)tlv->leaf_id, "sfile-name") == 0) {
            
            save_filter_present = true;
        }        
    }

    if (inc_exc_pattern_present && patt_rc && !count_filter_present && !save_filter_present) {

        render_line (Obuffer, msg_len);
    }

    return 0;
}
