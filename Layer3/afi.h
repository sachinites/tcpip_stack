/*
 * =====================================================================================
 *
 *       Filename:  layer3.h
 *
 *    Description:  This file defines the routines for Address Family AFI
 *
 *        Version:  1.0
 *        Created:  Friday 6 December 2024 02:53:56  IST
 *       Revision:  1.0
 *       Compiler:  g++
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016),  
 *                          Juniper Networks(Apr 2017 - 2021), 
 *                          Cisco ( 2021 - 2023 ), 
 *                          Calix ( 2023 - Present )
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

#ifndef __AFI__H__
#define __AFI__H__

#define AFI4    1
#define AFI6    2

#include <stdint.h>

typedef struct addr4_ {

    uint32_t addr;
    uint8_t mask;

} addr4_t;

typedef struct addr6_ {

    uint8_t addr[16];
    uint16_t mask;

} addr6_t;

typedef struct addr46_ {

    uint8_t af;
    
    union {
        addr4_t v4addr;
        addr6_t v6addr;
    } u;

} addr46_t;

void 
addr46_init (char *ip6_addr, uint16_t mask, uint8_t af, addr46_t *addr);

char *
addr46_get_addr_str (char *buffer, addr46_t *addr);

#endif 