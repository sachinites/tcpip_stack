/*
 * =====================================================================================
 *
 *       Filename:  object_group_update.h
 *
 *    Description: This file defines the data structures for Object Group Update/Modification
 *
 *        Version:  1.0
 *        Created:  11/09/2022 08:47:29 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Cisco Systems
 *
 * =====================================================================================
 */

#ifndef __OBJ_GRP_UPDATE_
#define __OBJ_GRP_UPDATE_

#include <stdbool.h>
#include <stdint.h>
#include "../../utils.h"
#include "../../c-hashtable/hashtable.h"
#include "../../c-hashtable/hashtable_itr.h"


typedef struct object_group_ object_group_t;
typedef struct node_ node_t;
typedef struct access_list_ access_list_t;

typedef enum og_update_acl_stage_
{
    og_update_fsm_stage_init,
    og_update_fsm_access_list_stage_uninstall,
    og_update_fsm_access_list_stage_decompile,
    og_update_fsm_access_list_stage_og_association,
    og_update_fsm_access_list_stage_compile,
    og_update_fsm_access_list_stage_installation,
    og_update_fsm_access_list_stage_cleanup,
} og_update_acl_stage_t;

static c_string 
og_update_acl_stage_to_string(og_update_acl_stage_t stage) {

    switch(stage) {
        case     og_update_fsm_stage_init:
            return "og_update_fsm_stage_init";
    case og_update_fsm_access_list_stage_uninstall:
            return "og_update_fsm_access_list_stage_uninstall";
    case og_update_fsm_access_list_stage_decompile:
            return "og_update_fsm_access_list_stage_decompile";
    case og_update_fsm_access_list_stage_og_association:
            return "og_update_fsm_access_list_stage_og_association";
    case og_update_fsm_access_list_stage_compile:
            return "og_update_fsm_access_list_stage_compile";
    case og_update_fsm_access_list_stage_installation:
            return "og_update_fsm_access_list_stage_installation";
    case og_update_fsm_access_list_stage_cleanup:
            return "og_update_fsm_access_list_stage_cleanup";
    default :
            return NULL;
    }
}

typedef struct object_group_update_info_ {

    object_group_t *p_og;
    object_group_t *c_og;
    bool is_delete;
    og_update_acl_stage_t stage;
    hashtable_t *access_lists_ht;
    uint32_t access_list_processed_count;
    uint32_t access_list_to_be_processed_count;
    node_t *node;
    task_t *og_update_task;
} object_group_update_info_t;

void
object_group_update_referenced_acls (
        node_t *node, 
        object_group_t *p_og, 
        object_group_t *c_og, 
        bool is_delete);

void
object_group_update_reschedule_task(object_group_update_info_t *og_update_info);

#endif 
