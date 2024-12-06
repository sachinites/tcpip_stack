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

typedef struct afi4_ {

    uint32_t addr;
    uint8_t mask;

} afi4_t;

typedef struct afi6_ {

    uint16_t addr[8];
    uint16_t mask;

} afi6_t;


typedef struct afi46_ {

    uint8_t afi;
    
    union {
        afi4_t addr;
        afi6_t addr;
    } u;

} afi46_t;

void 
afi46_init (char *ipc6_addr, uint16_t mask, uint8_t afi_type, afi46_t *afi);

char *
afi46_get_addr_str (char *buffer, afi46_t *afi);

#endif 