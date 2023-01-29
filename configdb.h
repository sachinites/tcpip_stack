/*
 * =====================================================================================
 *
 *       Filename:  configdb.h
 *
 *    Description: This file defines the routines and structures for config commit in postresql db
 *
 *        Version:  1.0
 *        Created:  01/28/2023 10:31:18 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#ifndef __CONFIGDB__
#define __CONFIGDB__

typedef struct node_ node_t ;

void node_config_db_init (node_t *node);

#endif 
