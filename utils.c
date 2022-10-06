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

#include <arpa/inet.h> /*for inet_ntop & inet_pton*/
#include <stdint.h>
#include <memory.h>
#include <stdio.h>
#include <assert.h>
#include "utils.h"

/*Apply mask on prefix, and store result in 'str_prefix'
 *For eg : prefix = 122.1.1.1, mask 24, then str_prefix
  will store 122.1.1.0
 * */
void
apply_mask(unsigned char *prefix, char mask, unsigned char *str_prefix){

    uint32_t binary_prefix = 0;
    uint32_t subnet_mask = ~0;

    if(mask == 32){
        strncpy((char *)str_prefix, prefix, 16);
        str_prefix[15] = '\0';
        return;
    }
    /*Convert Given IP address into binary format*/
    binary_prefix = tcp_ip_covert_ip_p_to_n(prefix);

    /*Compute Mask in binary format as well*/
    subnet_mask = subnet_mask << (32 - mask);

    /*Perform logical AND to apply mask on IP address*/
    binary_prefix = binary_prefix & subnet_mask;

    /*Convert the Final IP into string format again*/
    tcp_ip_covert_ip_n_to_p(binary_prefix, str_prefix);
}

void
layer2_fill_with_broadcast_mac(unsigned char *mac_array){

    mac_array[0] = 0xFF;
    mac_array[1] = 0xFF;
    mac_array[2] = 0xFF;
    mac_array[3] = 0xFF;
    mac_array[4] = 0xFF;
    mac_array[5] = 0xFF;
}

unsigned char *
tcp_ip_covert_ip_n_to_p(uint32_t ip_addr, 
                                        unsigned char *output_buffer){

    memset(output_buffer, 0, 16);
    ip_addr = htonl(ip_addr);
    inet_ntop(AF_INET, &ip_addr, output_buffer, 16);
    output_buffer[15] = '\0';
    return output_buffer;
}

uint32_t
tcp_ip_covert_ip_p_to_n(unsigned char *ip_addr){

    uint32_t binary_prefix = 0;
    inet_pton(AF_INET, ip_addr, &binary_prefix);
    binary_prefix = htonl(binary_prefix);
    return binary_prefix;
}

byte *
tlv_buffer_insert_tlv(byte  *buff,
                                  uint8_t tlv_no,
                                  uint8_t data_len,
                                  byte  *data){

    *buff = tlv_no;
    *(buff+1) = data_len;
    memcpy(buff + TLV_OVERHEAD_SIZE, data, data_len);
    return buff + TLV_OVERHEAD_SIZE + data_len;
}

byte  *
tlv_buffer_get_particular_tlv(byte  *tlv_buff, /*Input TLV Buffer*/
                      uint32_t tlv_buff_size,               /*Input TLV Buffer Total Size*/
                      uint8_t tlv_no,                            /*Input TLV Number*/
                      uint8_t *tlv_data_len){              /*Output TLV Data len*/

    byte tlv_type, tlv_len, *tlv_value = NULL;
    
    ITERATE_TLV_BEGIN(tlv_buff, tlv_type, tlv_len, tlv_value, tlv_buff_size){
        
        if(tlv_type != tlv_no) continue;
        *tlv_data_len = tlv_len;
        return tlv_value;
    }ITERATE_TLV_END(tlv_buff, tlv_type, tlv_len, tlv_value, tlv_buff_size); 

    *tlv_data_len = 0;

    return NULL;
}

uint32_t get_new_ifindex(){

	static uint32_t ifindex = 100;
	return (++ifindex);
}

/* Range to prefix/wildcard conversions for uint16_t*/

typedef struct {
    int count;
    uint16_t (*data)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT];
    uint16_t (*mask)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT];
} acl_port_range_masks_t;

typedef struct {
    uint16_t lb;
    uint16_t ub;
} acl_port_range_t;

static int
range2mask_rec(acl_port_range_masks_t *masks, acl_port_range_t range,
               uint16_t prefix, uint16_t mask, int b)
{   
    int ret;

    if ( prefix >= range.lb && (prefix | mask) <= range.ub ) {
        if ( masks->count >= MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT ) {
            assert(0);
        }
        (*(masks->data))[masks->count] = htons(prefix);
        (*(masks->mask))[masks->count] = htons(mask);
        masks->count++;
        return 0;
    } else if ( (prefix | mask) < range.lb || prefix > range.ub ) {
        return 0;
    } else {
        /* Partial */
    }
    if ( !mask ) {
        /* End of the recursion */
        return 0;
    }

    mask >>= 1;
    /* Left */
    ret = range2mask_rec(masks, range, prefix, mask, b + 1);
    if ( ret < 0 ) {
        return ret;
    }
    /* Right */
    prefix |= (1 << (15 - b));
    ret = range2mask_rec(masks, range, prefix, mask, b + 1);
    if ( ret < 0 ) {
        return ret;
    }
    return 0;
}


static int
range2mask (acl_port_range_masks_t *masks, acl_port_range_t range)
{   
    int b;
    uint16_t x;
    uint16_t y;
    uint16_t prefix;
    uint16_t mask;

    masks->count = 0;
    for ( b = 0; b < 16; b++ ) {
        x = range.lb & (1 << (15 - b));
        y = range.ub & (1 << (15 - b));
        if ( x != y ) {
            /* The most significant different bit */
            break;
        }
    }
    if (b == 0) {
        mask = 0xFFFF;
    }
    else {
        mask = (1 << (16 - b)) - 1;
    }
    prefix = range.lb & ~mask;

    return range2mask_rec(masks, range, prefix, mask, b);
}

void
range2_prefix_wildcard_conversion (uint16_t lb,  /* Input Lower bound */
                                                            uint16_t ub, /* Input Upper Bound */
                                                            uint16_t (*prefix)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT],      /* Array of Prefix , Caller need to provide memory */
                                                            uint16_t (*wildcard)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT],  /* Array of Prefix , Caller need to provide memory */
                                                            int *n) {

    acl_port_range_t range;
    acl_port_range_masks_t masks;

    range.lb = lb;
    range.ub = ub;

    memset (&masks, 0, sizeof(masks));
    
    masks.data = prefix;
    masks.mask = wildcard;

    range2mask (&masks, range);
    *n = masks.count;
}

void
print_uint16_bits (uint16_t n) {

    int i;
    for (i = 15; i >= 0; i--) {
        if (n & (1 << i)) printf ("1");
        else printf("0");
    }
}

/* Range to prefix/wildcard conversions for uint32_t*/

typedef struct {
    int count;
    uint32_t (*data)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT];
    uint32_t (*mask)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT];
} acl_port_range_masks32_t;

typedef struct {
    uint32_t lb;
    uint32_t ub;
} acl_port_range32_t;

static int
range2mask_rec32(acl_port_range_masks32_t *masks, acl_port_range32_t range,
               uint32_t prefix, uint32_t mask, int b)
{   
    int ret;

    if ( prefix >= range.lb && (prefix | mask) <= range.ub ) {
        if ( masks->count >= MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT ) {
            assert(0);
        }
        (*(masks->data))[masks->count] = htonl(prefix);
        (*(masks->mask))[masks->count] = htonl(mask);
        masks->count++;
        return 0;
    } else if ( (prefix | mask) < range.lb || prefix > range.ub ) {
        return 0;
    } else {
        /* Partial */
    }
    if ( !mask ) {
        /* End of the recursion */
        return 0;
    }

    mask >>= 1;
    /* Left */
    ret = range2mask_rec32(masks, range, prefix, mask, b + 1);
    if ( ret < 0 ) {
        return ret;
    }
    /* Right */
    prefix |= (1 << (31 - b));
    ret = range2mask_rec32(masks, range, prefix, mask, b + 1);
    if ( ret < 0 ) {
        return ret;
    }
    return 0;
}


static int
range2mask32 (acl_port_range_masks32_t *masks, acl_port_range32_t range)
{   
    int b;
    uint32_t x;
    uint32_t y;
    uint32_t prefix;
    uint32_t mask;

    masks->count = 0;
    for ( b = 0; b < 32; b++ ) {
        x = range.lb & (1 << (31 - b));
        y = range.ub & (1 << (31 - b));
        if ( x != y ) {
            /* The most significant different bit */
            break;
        }
    }
    if (b == 0) {
        mask = 0xFFFFFFFF;
    }
    else {
        mask = (1 << (32 - b)) - 1;
    }
    prefix = range.lb & ~mask;

    return range2mask_rec32(masks, range, prefix, mask, b);
}

void
range2_prefix_wildcard_conversion32 (uint32_t lb,  /* Input Lower bound */
                                                            uint32_t ub, /* Input Upper Bound */
                                                            uint32_t (*prefix)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT],      /* Array of Prefix , Caller need to provide memory */
                                                            uint32_t (*wildcard)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT],  /* Array of Prefix , Caller need to provide memory */
                                                            int *n) {

    acl_port_range32_t range;
    acl_port_range_masks32_t masks;

    range.lb = lb;
    range.ub = ub;

    memset (&masks, 0, sizeof(masks));
    
    masks.data = prefix;
    masks.mask = wildcard;

    range2mask32 (&masks, range);
    *n = masks.count;
}

void
print_uint32_bits (uint32_t n) {

    int i;
    for (i = 31; i >= 0; i--) {
        if (n & (1 << i)) printf ("1");
        else printf("0");
    }
}


#if 0

int 
main(int arhc, char **argv) {

    uint32_t prefix[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT] = {0};
    uint32_t wcard[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT] = {0};

    int n = 0;

    range2_prefix_wildcard_conversion32(167772160, 184549375, &prefix, &wcard, &n);

    printf("n = %d\n", n);

    int i;
    for (i = 0; i < n; i++) {
        print_uint32_bits(prefix[i]);
        printf ("\n");
        print_uint32_bits(wcard[i]);
        printf("\n\n");
    }

    return 0;
}
#endif
