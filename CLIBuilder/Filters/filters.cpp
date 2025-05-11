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
 *        Company:  Brocade Communications(2012-2017)
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
#include <regex.h>
#include <pthread.h>
#include <stdlib.h>
#include <memory.h>
#include "../string_util.h"
#include "../libcli.h"
#include "A_B.h"

#define OBUFFER_SIZE  256
#define CUM_BUFFER_MAX_SIZE 4096 /* must match with MAX_MSG_SIZE*/
#define BYTE8ALIGN(n)   ((n + 7) & ~7)

static tlv_struct_t **filter_array = NULL;
static int filter_array_size = 0;
static unsigned char Obuffer[OBUFFER_SIZE] = {0};
static unsigned char Cumbuffer[CUM_BUFFER_MAX_SIZE] = {0};
static uint16_t cum_buffer_byte_cnt = 0;
static int count_lines = 0;
static bool count_filter_present = false;
FILE *fileptr = NULL;

extern bool TC_RUNNING ;
extern int UT_PARSER_MSG_Q_FD; 
static ABmgr_t *abmgr = NULL;
static pthread_spinlock_t cprintf_spinlock;

void 
init_filters () {

    pthread_spin_init (&cprintf_spinlock, 0);
}

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
    /* Reset the Cum buffer for the next show command */
    memset (Cumbuffer, 0, cum_buffer_byte_cnt);
    cum_buffer_byte_cnt = 0;
}

static void 
render_line (unsigned char *Obuffer, int msg_len) {

    if (TC_RUNNING) {
    /* If the Test case is running, then collect individual printf statements in a Cumbuffer
        until all the show o/p of the command is collected. */
        memcpy(Cumbuffer + cum_buffer_byte_cnt, Obuffer, msg_len);
        cum_buffer_byte_cnt += msg_len;
        return;
    }

    if (fileptr) {
        fwrite (Obuffer, 1, msg_len, fileptr);
        return;
    }

     printw("%s", Obuffer);
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
    
    if (fileptr) {
        fclose (fileptr);
        fileptr = NULL;
    }

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

     if (abmgr) {

        if (ABmgr_is_printable (abmgr)) { 
            ABmgr_print(abmgr, render_line);
        }
        ABmgr_destroy(abmgr);
        abmgr = NULL;
    }
}


/* override glibc printf */
int cprintf (const char* format, ...) {

    int i;
    va_list args;
    int msg_len;
    tlv_struct_t *tlv;
    bool patt_rc = false;
    bool inc_exc_pattern_present = false;

    pthread_spin_lock (&cprintf_spinlock);

    va_start(args, format);
    memset (Obuffer, 0, OBUFFER_SIZE);
    vsnprintf((char *)Obuffer, OBUFFER_SIZE, format, args);
    msg_len = strlen ((const char *)Obuffer);

    va_end(args);

#if 0
    /* Append \n if not appended by user. All cprintf must end with \n*/
    if (Obuffer[msg_len - 1] != '\n') {
        Obuffer[msg_len ] = '\n';
        msg_len++;
    }
#endif 

    if (filter_array_size == 0) {

         render_line (Obuffer, msg_len);
         pthread_spin_unlock (&cprintf_spinlock);
         return 0;
    }
    
    uint16_t u_val = 0, d_val = 0;

    for (i = 0; i < filter_array_size; i++) {
            
        tlv = filter_array[i];

        if (parser_match_leaf_id (tlv->leaf_id, "u-val")) {
            u_val = atoi((const char *)tlv->value);
            continue;
        }

        if (parser_match_leaf_id (tlv->leaf_id, "d-val")) {
            d_val = atoi((const char *)tlv->value);
            continue;
        }

        if (parser_match_leaf_id (tlv->leaf_id, "xincl-pattern")) {

            inc_exc_pattern_present = true;
            uint16_t incl_u_val = u_val;
            uint16_t incl_d_val = d_val;
            u_val = d_val = 0;

            if (ignore_sole_new_line(Obuffer, msg_len)) {
                pthread_spin_unlock(&cprintf_spinlock);
                return 0;
            }

            int match = regex_match ((const char *)Obuffer, 
                                        (const char *)tlv->value);
            
            patt_rc = (match == 0) ? true : false;

            if (!abmgr) {
                abmgr = ABmgr_get_instance (incl_u_val, incl_d_val);
            }

            if (ABmgr_insert_string(abmgr, (char *)Obuffer, msg_len, patt_rc, true)) {
                ABmgr_print(abmgr, render_line);
                ABmgr_reset(abmgr);
            }
            pthread_spin_unlock(&cprintf_spinlock);
            return 0;
        }

        else if (parser_match_leaf_id (tlv->leaf_id, "incl-pattern")) {

            inc_exc_pattern_present = true;
            uint16_t incl_u_val = u_val;
            uint16_t incl_d_val = d_val;
            u_val = d_val = 0;

            int match = regex_match ((const char *)Obuffer, 
                                        (const char *)tlv->value);

            patt_rc = (match == 0) ? true : false;

            if (!patt_rc) {
                pthread_spin_unlock (&cprintf_spinlock);
                return 0;
            }
        }
        
        else if (parser_match_leaf_id (tlv->leaf_id, "excl-pattern")) {

            inc_exc_pattern_present = true;
            uint16_t excl_u_val = u_val;
            uint16_t excl_d_val = d_val;
            u_val = d_val = 0;

            int match = regex_match ((const char *)Obuffer, 
                                        (const char *)tlv->value);
            
            patt_rc = (match != 0) ? true : false;

            if (!patt_rc) {
                pthread_spin_unlock (&cprintf_spinlock);
                return 0;
            }
        }

        else if (parser_match_leaf_id (tlv->leaf_id, "grep-pattern")) {
            
            inc_exc_pattern_present = true;
            uint16_t grep_u_val = u_val;
            uint16_t grep_d_val = d_val;
            u_val = d_val = 0;

            int match = regex_match ((const char *)Obuffer, 
                                        (const char *)tlv->value);

            patt_rc = (match == 0) ? true : false;

            if (!patt_rc) {
                 pthread_spin_unlock (&cprintf_spinlock);
                 return 0;
            }
        }

        else if (parser_match_leaf_id (tlv->value, "count")) {
            
            count_filter_present  = true;

            if (inc_exc_pattern_present) {
                if (patt_rc) count_lines++;
            }
            else {
                if (!ignore_sole_new_line  (Obuffer, msg_len)) count_lines++;
            }
        }
        else if (parser_match_leaf_id (tlv->leaf_id, "sfile-name")) {
            
            if (!fileptr) {
                fileptr = fopen ((const char *) tlv->value, "w+");
                assert(fileptr);
            }
        }
    }

    while (!count_filter_present ) {

        if (inc_exc_pattern_present ) {

            /* Ignore '\n' , '\r' , '\n\r' */
            if (ignore_sole_new_line  (Obuffer, msg_len)) break;

        }

        if (0 && Obuffer[msg_len - 1] != '\n') {
            Obuffer[msg_len ] = '\n';
            msg_len++;
        }

        render_line (Obuffer, msg_len);
        break;
    }

    pthread_spin_unlock (&cprintf_spinlock);
    return 0;
}
