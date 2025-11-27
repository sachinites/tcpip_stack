#ifndef __RTM_CMN__
#define __RTM_CMN__

#include <stdint.h>
#include "rtm_enums.h"

typedef struct bitmap_ bitmap_t;

#pragma pack(push, 8)

typedef struct rtm_prefix_ {

    union {
        uint32_t v4_addr;
        uint16_t v6_addr[8];
        uint32_t mpls_label;
        uint8_t mac_addr[6];
    } u;

    uint8_t prefix_len;
    RTM_AFI_T afi;

} rtm_prefix_t;


typedef struct rtm_label_ {

    uint32_t label_val;
    rtm_mpls_op_t op;

} rtm_label_t; 

#define MAX_LBL_DEPTH 8

typedef struct rtm_lstack_ {

    uint8_t curr_index;
    rtm_label_t labels[MAX_LBL_DEPTH];

} rtm_lstack_t;

#pragma pack(pop)

bool rtm_prefix_is_null (rtm_prefix_t *prefix);
void rtm_prefix_initialize_v4 (rtm_prefix_t *prefix, uint32_t ip_addr, uint8_t mask);
void rtm_prefix_initialize_v6 (rtm_prefix_t *prefix, uint8_t addr[16], uint8_t mask);

/* Helper Functions for Prefix to Bitmap Conversion */
void rtm_prefix_to_bitmap(rtm_prefix_t *prefix, bitmap_t *bm);
void rtm_prefix_to_wildcard_bitmap(rtm_prefix_t *prefix, bitmap_t *wildcard);

int8_t
rtm_prefix_compare(const rtm_prefix_t *p1, const rtm_prefix_t *p2) ;

#define RTM_UP_TIME(time_t_obj, buff, size)	\
	hrs_min_sec_format((unsigned int)difftime(time(NULL), \
                                        time_t_obj), buff, size)
                                        
#endif 