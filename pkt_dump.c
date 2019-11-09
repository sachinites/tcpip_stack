/*
 * =====================================================================================
 *
 *       Filename:  pkt_dump.c
 *
 *    Description:  This file implements the routine to dump packet content field by field
 *
 *        Version:  1.0
 *        Created:  11/03/2019 01:51:00 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Juniper Networks (https://csepracticals.wixsite.com/csepracticals), sachinites@gmail.com
 *        Company:  Juniper Networks
 *
 *        This file is part of the NetworkGraph distribution (https://github.com/sachinites) 
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

#include "Layer2/layer2.h"
#include "tcpconst.h"
#include <stdio.h>

/* Implement below function to print all necessary headers
 * of the packet including : 
 * Ethernet Hdr
 * ARP hdr
 * IP Hdr
 * For Unknown payload type (application data) , just
 * print the offset and size of payload in the frame.
 * 
 * We shall be using below API to verify our code changes
 * are correct or not for catching early bugs !!
 * */

void
pkt_dump(ethernet_hdr_t *ethernet_hdr, 
         unsigned int pkt_size){

    /*Assignment*/    
}

