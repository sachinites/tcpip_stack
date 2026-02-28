/*
 * =====================================================================================
 *
 *       Filename:  layer2.h
 *
 *    Description: This file defines the structures required for Layer 2 functionality 
 *
 *        Version:  1.0
 *        Created:  Saturday 21 September 2019 09:51:27  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *        
 *        This file is part of the NetworkGraph distribution (https://github.com/sachinites).
 *        Copyright (c) 2017 Abhishek Sagar.
 *        This program is free software: you can redistribute it and/or modify
 *        it under the terms of the GNU General Public License as published by  
 *        the Free Software Foundation, version 3.
 *
 *        This program is distributed in the hope that it will be useful, but 
 *        WITHOUT ANY WARRANTY; without even the implied warranty of 
 *        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 *        General Public License for more details.
 *
 *        You should have received a copy of the GNU General Public License 
 *        along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * =====================================================================================
 */

#ifndef __LAYER2__
#define __LAYER2__

#include <stdlib.h>  /*for calloc*/
#include <stdint.h>
#include "../net.h"
#include "../gluethread/glthread.h"
#include "../tcpconst.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../Interface/InterfacEnums.h"

typedef struct node_ node_t;


/*APIs to be used to create topologies*/
void
node_set_intf_l2_mode(node_t *node, const char *intf_name, IntfL2Mode intf_l2_mode);

void
node_set_intf_switchport(node_t *node, const char *intf_name) ;

void
node_set_intf_vlan_membership(node_t *node, const char *intf_name, vlan_id_t vlan_id, bool IsTrunk);

#endif /* __LAYER2__ */
