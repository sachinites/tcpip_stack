/*
 * =====================================================================================
 *
 *       Filename:  tcp_ip_trace.h
 *
 *    Description:  This file declares the routines for tracing
 *
 *        Version:  1.0
 *        Created:  06/24/2020 08:09:39 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Juniper Networks (https://csepracticals.wixsite.com/csepracticals), sachinites@gmail.com
 *        Company:  Juniper Networks
 *
 *        This file is part of the TCP/IP Stack distribution (https://github.com/sachinites) 
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

#ifndef __TCP_IP_TRACE__
#define __TCP_IP_TRACE__

typedef enum{

    ETH_HDR,
    IP_HDR
} hdr_type_t;

void
tcp_dump(int sock_fd, char *pkt, uint32_t pkt_size,
            hdr_type_t hdr_type);


#endif /* __TCP_IP_TRACE__ */
