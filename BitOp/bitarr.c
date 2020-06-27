/*
 * =====================================================================================
 *
 *       Filename:  bitarr.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  Sunday 04 March 2018 06:23:30  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *        
 *        This file is part of the TCP/Ipo Stack distribution (https://github.com/sachinites).
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

#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include "bitsop.h"
#include "bitarr.h"

#define CHAR_SIZE   8

void
init_bit_array(bit_array_t *bitarr, unsigned int n_bits){

    unsigned int n_byte_blocks = n_bits/CHAR_SIZE;

    if(n_bits % CHAR_SIZE)
        n_byte_blocks++;
    if(!bitarr->array)
        bitarr->array = calloc(1, n_byte_blocks);
    else
        memset(bitarr->array, 0, n_byte_blocks);
    bitarr->size = n_bits;
    bitarr->trail_bits = n_bits % CHAR_SIZE;
}

void
set_bit(bit_array_t *bitarr, unsigned int index){

    if(index >= bitarr->size){
        printf("%u is out of array bounds [%u,%u]\n", 
            index, 0, bitarr->size -1);
        return;
    }

    unsigned byte_block = 0,
             residual_bit = 0;

    byte_block = index / CHAR_SIZE;
    residual_bit = index % CHAR_SIZE;

#if 0    
    assert(bitarr->size/CHAR_SIZE == byte_block && 
        bitarr->trail_bits >= residual_bit);
#endif

    char *ptr = bitarr->array + byte_block;
    SET_BIT((*ptr), (CHAR_SIZE - residual_bit));
}

void
unset_bit(bit_array_t *bitarr, unsigned int index){

    if(index >= bitarr->size){
        printf("%u is out of array bounds [%u,%u]\n", 
            index, 0, bitarr->size -1);
        return;
    }

    unsigned byte_block = 0,
             residual_bit = 0;

    byte_block = index / CHAR_SIZE;
    residual_bit = index % CHAR_SIZE;

#if 0
    assert(bitarr->size/CHAR_SIZE == byte_block && 
        bitarr->trail_bits >= residual_bit);
#endif

    char *ptr = bitarr->array + byte_block;
    UNSET_BIT((*ptr), (CHAR_SIZE - residual_bit));
}

char
is_bit_set(bit_array_t *bitarr, unsigned int index){

    
    if(index >= bitarr->size){
        printf("%u is out of array bounds [%u,%u]\n", 
            index, 0, bitarr->size -1);
        return 0;
    }

    unsigned byte_block = 0,
             residual_bit = 0;

    byte_block = index / CHAR_SIZE;
    residual_bit = index % CHAR_SIZE;
    
#if 0
    assert(bitarr->size/CHAR_SIZE == byte_block && 
        bitarr->trail_bits >= residual_bit);
#endif
    char *ptr = bitarr->array + byte_block;
    return (char)(IS_BIT_SET((*ptr), (CHAR_SIZE - residual_bit)));
}

unsigned int
get_next_available_bit(bit_array_t *bitarr){

    unsigned int i = 0;
    for(; i < bitarr->size; i++){
        if(is_bit_set(bitarr, i))
            continue;
        return i;
    }
    return 0xFFFFFFFF;
}

void
print_bit_array(bit_array_t *bitarr){

    unsigned int i = 0, index = 0,
                 byte_blocks = 0,
                 residual_bits = 0;

    int j = 0;

    byte_blocks = bitarr->size / CHAR_SIZE;
    residual_bits = bitarr->size % CHAR_SIZE;
    //assert(bitarr->trail_bits >= residual_bit);
    char *ptr = bitarr->array;
    char byte = 0;

    for( ; i < byte_blocks; i++){
        byte = *(ptr+i);
        for(j = 7; j >= 0; j--, index++){
            printf("[%u] : %c\n", index, IS_BIT_SET(byte, j) ? '1' : '0');
        }
    }

    if(!residual_bits)
        return;

    byte = *(ptr+i);
    for(j = 7; j >= CHAR_SIZE - residual_bits; j--, index++){
        printf("[%u] : %c\n", index, IS_BIT_SET(byte, j) ? '1' : '0');
    }
}

#if 0
int
main(int argc, char **argv){

    bit_array_t *arr = XCALLOC(1, bit_array_t);
    init_bit_array(arr, 15);
    set_bit(arr, 11);
    set_bit(arr, 21);
    set_bit(arr, 30);
    set_bit(arr, 3);
    set_bit(arr, 33);
    print_bit_array(arr);
    unset_bit(arr, 11);
    print_bit_array(arr);
    return 0;
}
#endif
