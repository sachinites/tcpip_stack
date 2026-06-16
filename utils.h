/*
 * =====================================================================================
 *
 *       Filename:  enums.h
 *
 *    Description:  This file contains the decalaration of all enumerations used in this file
 *
 *        Version:  1.0
 *        Created:  Wednesday 18 September 2019 02:38:12  IST
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
/* Visit my Website for more wonderful assignments and projects :
 * www.csepracticals.com
 * if above URL dont work, then try visit : https://www.csepracticals.com*/

#ifndef __UTILS__
#define __UTILS__

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "libs/common/cmn_prefix.h"

typedef unsigned char byte;
typedef unsigned char* c_string; 
typedef void unused;
typedef uint16_t vlan_id_t;

#define TO_BE_OVERRIDDEN_BY_DERIEVED_CLASS    assert(0)

void
apply_mask(c_string prefix, char mask, c_string str_prefix);

void
layer2_fill_with_broadcast_mac(c_string mac_array);

#define IS_MAC_BROADCAST_ADDR(mac)   \
    (mac[0] == 0xFF  &&  mac[1] == 0xFF && mac[2] == 0xFF && \
     mac[3] == 0xFF  &&  mac[4] == 0xFF && mac[5] == 0xFF)


#define TLV_OVERHEAD_SIZE  2

static inline uint32_t
tlv_read_u32(const byte *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

/*Macro to Type Length Value reply
 * byte * - start_ptr, IN
 * unsigned char - type, OUT
 * unsigned char - length, OUT
 * unsigned char * - tlv_ptr, OUT
 * unsigned int - total_size(excluding first 2 bytes of Type, Len), IN
 * */
#define ITERATE_TLV_BEGIN(start_ptr, type, length, tlv_ptr, tlv_size)           \
{                                                                               \
    unsigned int _len = 0; byte _tlv_value_size = 0;                   \
    type = 0; length = 0; tlv_ptr = NULL;                                       \
    for(tlv_ptr = (unsigned char *)start_ptr +                                  \
             TLV_OVERHEAD_SIZE; _len < tlv_size;                                \
            _len += _tlv_value_size + TLV_OVERHEAD_SIZE,                        \
             tlv_ptr = (tlv_ptr + TLV_OVERHEAD_SIZE + length)){                 \
        /* Safety check: ensure we have space for TLV header */                \
        if (_len + TLV_OVERHEAD_SIZE > tlv_size) break;                        \
        type = *(tlv_ptr - TLV_OVERHEAD_SIZE);                                  \
        _tlv_value_size = (byte)(*(tlv_ptr -                           \
            TLV_OVERHEAD_SIZE + sizeof(byte)));                        \
        /* Safety check: ensure TLV data doesn't exceed buffer */              \
        if (_len + TLV_OVERHEAD_SIZE + _tlv_value_size > tlv_size) break;      \
        length = _tlv_value_size;

#define ITERATE_TLV_END(start_ptr, type, length, tlv_ptr, tlv_size)             \
    }}

byte *
tlv_buffer_get_particular_tlv(byte *tlv_buff, /*Input TLV Buffer*/
                              uint32_t tlv_buff_size, /*Input TLV Buffer Total Size*/
                              uint8_t tlv_no, /*Input TLV Number*/
                              uint8_t *tlv_data_len); /*Output TLV Data len*/

byte *
tlv_buffer_insert_tlv(byte *tlv_buff, uint8_t tlv_no, 
                     uint8_t data_len, byte *data);

unsigned char *
tcp_ip_covert_ip_n_to_p(uint32_t ip_addr, 
                        c_string output_buffer);

uint32_t
tcp_ip_convert_ip_p_to_n(c_string ip_addr);

static inline uint32_t
tcp_ip_convert_dmask_to_bin_mask(uint8_t dmask) {

    uint32_t bin_mask = 0xFFFFFFFF;
    if (dmask == 0) return 0;
    /* dont use below code for dmask = 0, undefined behavior */
    bin_mask = (bin_mask >> (32 - dmask));
    bin_mask = (bin_mask << (32 - dmask));
    return bin_mask;
}

bool IsSameSubnet(
        uint32_t network_ip_addr, 
        uint8_t mask, 
        uint32_t addr);

static inline uint8_t
tcp_ip_convert_bin_mask_to_dmask(uint32_t bin_mask) {

    uint8_t cnt = 0;

    while(bin_mask) {
        cnt++;
        bin_mask = bin_mask << 1;
    }
    return cnt;
}

#define UNUSED(variable)    (void)variable

#define MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT 64

void
range2_prefix_wildcard_conversion (uint16_t lb,  /* Input Lower bound */
                                                            uint16_t ub, /* Input Upper Bound */
                                                            uint16_t (*prefix)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT],      /* Array of Prefix , Caller need to provide memory */
                                                            uint16_t (*wildcard)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT],  /* Array of Prefix , Caller need to provide memory */
                                                            int *n);

void print_uint16_bits (uint16_t n);
void print_uint32_bits (uint32_t n);

void
range2_prefix_wildcard_conversion32 (uint32_t lb,  /* Input Lower bound */
                                                                uint32_t ub, /* Input Upper Bound */
                                                                uint32_t (*prefix)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT],      /* Array of Prefix , Caller need to provide memory */
                                                                uint32_t (*wildcard)[MAX_PREFIX_WLDCARD_RANGE_CONVERSION_FCT],  /* Array of Prefix , Caller need to provide memory */
                                                                int *n);

#define string_compare(a, b, len) (strncmp((const char *)a, (const char *)b, len))
#define string_copy(dst, src, len) (strncpy((char *)dst, (const char *)src, len))
bool  mac_address_compare ( unsigned char *mac1, unsigned char *mac2);

#define HRS_MIN_SEC_FMT_TIME_LEN    24
c_string
hrs_min_sec_format(unsigned int seconds, c_string time_f, size_t size);

c_string
hrs_min_sec_ms_format(uint64_t elapsed_ms, c_string time_f, size_t size);

uint64_t
wall_clock_ms_now(void);

#define DEADCODE    (assert(0))
#define PERCENT_ASCII_CODE  37

#define ConsOut printw

#define TABS(n)            \
do{                                  \
   unsigned short _i = 0;  \
   for(; _i < n; _i++)         \
       cprintf("  ");               \
} while(0);

/* To be used for comparison fns*/
typedef enum comp_fn_res_ {

    CMP_PREFERRED  =   -1,
    CMP_NOT_PREFERRED = 1,
    CMP_PREF_EQUAL = 0
} comp_fn_res_t;

void 
tcp_ip_generate_random_mac_address (unsigned char (*mac)[6]) ;

uint32_t apply_mask2 (uint32_t prefix, uint8_t mask);
uint16_t afi_stride_len (AFI_T afi) ;


static const char* afi_to_string(AFI_T afi) {
    switch(afi) {
        case AF_IPV4: return "IPv4";
        case AF_IPV6: return "IPv6";
        case AF_LABEL: return "MPLS";
        case AF_MAC: return "MAC";
        default: return "Unknown";
    }
}

#define RTM_UP_TIME(time_t_obj, buff, size)	\
	hrs_min_sec_format((unsigned int)difftime(time(NULL), \
                                        time_t_obj), buff, size)

#endif /* __UTILS__ */
