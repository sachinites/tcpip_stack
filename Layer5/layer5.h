/*
 * =====================================================================================
 *
 *       Filename:  layer5.h
 *
 *    Description:  This file decines the structures and routines for Application LAyer
 *
 *        Version:  1.0
 *        Created:  05/30/2020 11:09:53 AM
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

#ifndef __LAYER5__
#define __LAYER5__

#include "../tcpip_app_register.h"

void
tcp_app_register_l2_protocol_interest(uint32_t L5_protocol,
        app_layer_cb _app_layer_cb);


void
tcp_app_register_l3_protocol_interest(uint32_t L5_protocol,
        app_layer_cb _app_layer_cb);

void
tcp_app__deregister_l2_protocol_interest(uint32_t L5_protocol,
        app_layer_cb _app_layer_cb);

void
tcp_app__deregister_l3_protocol_interest(uint32_t L5_protocol,
        app_layer_cb _app_layer_cb);

#endif /* __LAYER5__ */
