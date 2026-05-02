/* This file Implemented FLAT DPDK like Ipv4 routing table ( should be extendable to
    ipv6 later by AI ). Table wil of two levels - 16 bit stride length for each level.
*/

#ifndef __FLAT_RT__
#define __FLAT_RT__

#include <stdint.h>
#include <atomic>
#include <cmath>

#define FLAT_RT_V4 0
#define FLAT_RT_V6 1

#define STRIDE_LEN 16
#define LEVEL_MAX_ENTRIES (std::pow(2 , STRIDE_LEN))

typedef enum mtrie_ops_result_code_ {

	FLAT_RT_INSERT_SUCCESS,
	FLAT_RT_INSERT_FAILED,
	FLAT_RT_INSERT_DUPLICATE,
	FLAT_RT_DELETE_SUCCESS,
	FLAT_RT_DELETE_FAILED,
	FLAT_RT_LOOKUP_SUCCESS,
	FLAT_RT_LOOKUP_FAILED,
	FLAT_RT_OPS_UNKNOWN

} mtrie_ops_result_code_t;

#pragma pack(push, 8)

typedef struct flat_rt_lvl_ flat_rt_lvl_t;

typedef struct flt_rt_entry_
{

    /* Application data ( The nexthop(s) )*/
    std::atomic<void *> app_data;

    /* Pointer to next level array */
    std::atomic<flat_rt_lvl_t *> next_lvl;

} flat_rt_entry_t;

struct flat_rt_lvl_
{

    flat_rt_entry_t entries[LEVEL_MAX_ENTRIES];
    /* Only accessible by writer , so need of atomic */
    /* Number of application data and children per children,
        useful to determine if the level is empty and could be
        deleted */
    uint32_t num_datas;
    uint32_t num_children;
};

typedef struct flat_rt_
{

    uint8_t afi;
    flat_rt_lvl_t *level0;

} flat_rt_t;


#pragma pack(pop)


mtrie_ops_result_code_t
flat_rt_v4_insert (flat_rt_t *rt, 
                   uint32_t prefix, 
                   uint8_t prefix_len, 
                   void *app_data, 
                   flat_rt_lvl_t **discard_level_out);



#endif