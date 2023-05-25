/*
 * =====================================================================================
 *
 *       Filename:  tcp_stack_init.c
 *
 *    Description:  This file implements the routine to initialize the TCP/IP stacl
 *
 *        Version:  1.0
 *        Created:  01/11/2020 11:05:13 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Juniper Networks (www.csepracticals.com), sachinites@gmail.com
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
 *        visit website : www.csepracticals.com for more courses and projects
 *                                  
 * =====================================================================================
 */

#include <unistd.h>

extern void init_spf_algo();
extern void network_start_pkt_receiver_thread();
extern void isis_one_time_registration();
extern void ut_parser_init();

#include "EventDispatcher/event_dispatcher.h"
event_dispatcher_t gev_dis;

void
init_tcp_ip_stack(){

	event_dispatcher_run(&gev_dis);   
    init_spf_algo();
	isis_one_time_registration();
	network_start_pkt_receiver_thread();
	ut_parser_init();
}
