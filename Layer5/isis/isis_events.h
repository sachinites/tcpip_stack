/*
 * =====================================================================================
 *
 *       Filename:  isis_events.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  11/14/2021 10:02:57 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#ifndef __ISIS_EVENTS__
#define __ISIS_EVENTS__

typedef enum isis_events_ {

    isis_event_none,
    /*lspdb update events begin*/
    isis_event_self_duplicate_lsp,
    isis_event_self_fresh_lsp,
    isis_event_self_new_lsp,
    isis_event_self_old_lsp,
    isis_event_max
} isis_event_type_t;

const char *
isis_event_str(isis_event_type_t isis_event_type);

#endif