/*
 * =====================================================================================
 *
 *       Filename:  bitarr.h
 *
 *    Description:  Interface to Bit Array
 *
 *        Version:  1.0
 *        Created:  Sunday 04 March 2018 06:20:07  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *        
 *        This file is part of the BIT Array distribution (https://github.com/sachinites).
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

#ifndef __BIT_ARRAY__
#define __BIT_ARRAY__

typedef struct _bit_array{
    unsigned int size;
    char *array;
    char trail_bits;
} bit_array_t;

void 
init_bit_array(bit_array_t *bitarr, unsigned int size);

void
set_bit(bit_array_t *bitarr, unsigned int index);

void
unset_bit(bit_array_t *bitarr, unsigned int index);

char
is_bit_set(bit_array_t *bitarr, unsigned int index);

unsigned int
get_next_available_bit(bit_array_t *bitarr);

#endif /* __BIT_ARRAY__ */
