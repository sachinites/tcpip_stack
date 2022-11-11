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
#include "../../c-hashtable/hashtable.h"
#include "../../c-hashtable/hashtable_itr.h"


typedef struct object_group_ object_group_t;
typedef struct node_ node_t;

void
object_group_update_referenced_acls (
        node_t *node, 
        object_group_t *p_og, 
        object_group_t *c_og, 
        bool is_delete);

#endif 
