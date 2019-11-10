/*
 * =====================================================================================
 *
 *       Filename:  ddcp.h
 *
 *    Description:  This file implements the definition of structures and declaratio ofpublic APIs related to DDCP (Distributed Data Collection Protocol)
 *
 *        Version:  1.0
 *        Created:  11/09/2019 02:07:34 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Juniper Networks (https://csepracticals.wixsite.com/csepracticals), sachinites@gmail.com
 *        Company:  Juniper Networks
 *
 *        This file is part of the DDCP distribution (https://github.com/sachinites) 
 *        Copyright (c) 2019 Abhishek Sagar.
 *        This program is free software: you can redistribute it and/or modify it under the terms of the GNU General 
 *        Public License as published by the Free Software Foundation, version 3.
 *        
 *        This program is distributed in the hope that it will be useful, but
 *        WITHOUT ANY WARRANTY; without even the implied warranty of
 *        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *        General Public License for more details.
 *
 *        visit website : https://csepracticals.wixsite.com/csepracticals for more courses and projects
 *                                  
 * =====================================================================================
 */

#ifndef __DDCP__
#define __DDCP__

#include "../../utils.h"
#include "../../graph.h"
#include "../../Layer2/layer2.h"

typedef enum{

    DDCP_TLV_RTR_NAME,
    DDCP_TLV_RTR_LO_ADDR,
    DDCP_TLV_RAM_SIZE,
    DDCP_TLV_OS_VERSION,
    DDCP_TLV_MAX
} DDCP_TLV_ID;

typedef struct ddcp_query_hdr_{
    char ddcp_msg_type;
    unsigned int originator_ip;
    unsigned int no_of_tlvs;
    DDCP_TLV_ID tlv_code_points[0];
} ddcp_query_hdr_t;

typedef struct ddcp_interface_prop_{

    bool_t is_enabled; 
} ddcp_interface_prop_t;


void
init_ddcp_interface_props(ddcp_interface_prop_t **ddcp_interface_prop);

static inline bool_t
is_interface_ddcp_enabled(ddcp_interface_prop_t *ddcp_interface_prop){

    return ddcp_interface_prop->is_enabled;
}

void
ddcp_send_ddcp_query_out(char *pkt, 
                         unsigned int pkt_size, 
                         interface_t *oif);

void
ddcp_flood_ddcp_query_out(char *pkt, 
                          unsigned int pkt_size,
                          interface_t *exempted_intf);

void
ddcp_process_ddcp_hdr(node_t *node, interface_t *iif,
                      ethernet_hdr_t *ethernet_hdr,
                      unsigned int pkt_size);
#endif /*__DDCP__*/
