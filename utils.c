/*
 * =====================================================================================
 *
 *       Filename:  utils.c
 *
 *    Description: This file contains general utility routines 
 *
 *        Version:  1.0
 *        Created:  Saturday 21 September 2019 06:03:54  IST
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

#include "utils.h"
#include <sys/socket.h>
#include <arpa/inet.h> /*for inet_ntop & inet_pton*/
#include <stdint.h>
#include <string.h>

/*Apply mask on prefix, and store result in 'str_prefix'
 *For eg : prefix = 122.1.1.1, mask 24, then str_prefix
  will store 122.1.1.0
 * */
void
apply_mask(char *prefix, char mask, char *str_prefix){

    uint32_t binary_prefix = 0;
    uint32_t subnet_mask = 0xFFFFFFFF;

    if(mask == 32){
        strncpy(str_prefix, prefix, 16);
        str_prefix[15] = '\0';
        return;
    }
    /*Convert Given IP address into binary format*/
    inet_pton(AF_INET, prefix, &binary_prefix);
    binary_prefix = htonl(binary_prefix);

    /*Compute Mask in binary format as well*/
    subnet_mask = subnet_mask << (32 - mask);

    /*Perform logical AND to apply mask on IP address*/
    binary_prefix = binary_prefix & subnet_mask;

    /*Convert the Final IP into string format again*/
    binary_prefix = htonl(binary_prefix);
    inet_ntop(AF_INET, &binary_prefix, str_prefix, 16);
    str_prefix[15] = '\0';
}

void
layer2_fill_with_broadcast_mac(char *mac_array){

    mac_array[0] = 0xFF;
    mac_array[1] = 0xFF;
    mac_array[2] = 0xFF;
    mac_array[3] = 0xFF;
    mac_array[4] = 0xFF;
    mac_array[5] = 0xFF;
}

char *
tcp_ip_covert_ip_n_to_p(uint32_t ip_addr,
        char *output_buffer){

    char *out = NULL;
    static char str_ip[16];
    out = !output_buffer ? str_ip : output_buffer;
    memset(out, 0, 16);
    ip_addr = htonl(ip_addr);
    inet_ntop(AF_INET, &ip_addr, out, 16);
    out[15] = '\0';
    return out;
}

uint32_t
tcp_ip_covert_ip_p_to_n(char *ip_addr){

    uint32_t binary_prefix = 0;
    inet_pton(AF_INET, ip_addr, &binary_prefix);
    binary_prefix = htonl(binary_prefix);
    return binary_prefix;
}


