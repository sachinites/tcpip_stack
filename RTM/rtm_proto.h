#ifndef __RTM_PROTO__
#define __RTM_PROTO__

#include <stdint.h>
#include "rtm_enums.h"
#include "rtm_error.h"
#include "../Tree/libtree.h"
#include "../common/cmn_prefix.h"

typedef struct rtm_ rtm_t;
typedef struct vrf_ vrf_t;
typedef struct node_ node_t;

#pragma pack(push, 8)

typedef struct rtm_nh_proto_
{
    /* Keys */
    RTM_PROTO_T proto;
    RTM_SUB_PROTO_T sub_proto;
    uint32_t instance_no;
    uint8_t vrf_id;

    union
    {

        struct
        {

        } statc;

        struct
        {

        } connected;

        struct
        {

        } local;

        struct
        {

        } isis;

        struct
        {

        } ospf;

        struct
        {

        } bgp;

        struct
        {

        } ldp;

        struct
        {

        } sr;

        struct
        {

        } srte;

    } u;

    /* Glue for rtm_t->nh_proto_info_tree */
    avltree_node_t proto_glue;

    uint32_t ref_count;

} rtm_nh_proto_t;

#pragma pack(pop)

void 
rtm_nh_proto_initialize(rtm_nh_proto_t *nh_proto);

rtm_error_t
rtm_nh_proto_info_create(
                         const RTM_PROTO_T proto,
                         const RTM_SUB_PROTO_T sub_proto,
                         const uint32_t inst_no,
                         const uint8_t vrf_id,
                         rtm_nh_proto_t **out);

/* Compare only keys*/
int8_t
rtm_nh_proto_compare(rtm_nh_proto_t *nh_proto1, rtm_nh_proto_t *nh_proto2);

/* Compare all fields */
int8_t 
rtm_nh_proto_is_equal ( rtm_nh_proto_t *nh_proto1, rtm_nh_proto_t *nh_proto2);

rtm_error_t
rtm_nh_proto_add(rtm_t *rtm, rtm_nh_proto_t *nh_proto, rtm_nh_proto_t **existing_nh_proto_out);

void 
rtm_nh_proto_copy(rtm_nh_proto_t *src_nh_proto, rtm_nh_proto_t *dst_nh_proto);

rtm_nh_proto_t *
rtm_nh_proto_lookup(const rtm_t *rtm, rtm_nh_proto_t *nh_proto_template);

void rtm_nh_proto_reference(rtm_nh_proto_t *nh_proto);

void rtm_nh_proto_dereference(rtm_t *rtm, rtm_nh_proto_t *nh_proto);

rtm_t *rtm_get_route_target_rtm(node_t *node,
                          vrf_t *vrf, AFI_T afi, 
                          RTM_PROTO_T proto, 
                          RTM_SUB_PROTO_T sub_proto);

/* ----------------------------------------------------------------  */


#pragma pack(push, 8)

typedef struct rtm_proto_info_ {

    /* Keys */
    RTM_PROTO_T proto;
    uint32_t instance_no;
    uint8_t vrf_id;
    
    avltree_node_t proto_glue;
    avltree_t sub_db;
    
} rtm_proto_info_t;

#pragma pack(pop)

rtm_proto_info_t *
rtm_proto_info_create (rtm_t *rtm, RTM_PROTO_T proto, uint32_t inst_no);

int8_t
rtm_proto_compare (rtm_proto_info_t* nh_proto1, rtm_proto_info_t* nh_proto2);

rtm_error_t 
rtm_proto_info_add (const rtm_t* rtm, rtm_proto_info_t* proto_info);

rtm_error_t 
rtm_proto_info_del (const rtm_t* rtm, RTM_PROTO_T proto, uint32_t inst_no);

rtm_proto_info_t *
rtm_proto_lookup(const rtm_t* rtm, RTM_PROTO_T proto, uint32_t inst_no);

#endif 