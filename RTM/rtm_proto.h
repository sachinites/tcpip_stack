#ifndef __RTM_PROTO__
#define __RTM_PROTO__

#include <stdint.h>
#include "rtm_enums.h"
#include "rtm_error.h"
#include "../Tree/libtree.h"

typedef struct rtm_ rtm_t;

typedef struct nh_proto_
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

rtm_error_t
rtm_nh_proto_info_create(rtm_t *rtm,
                         const RTM_PROTO_T proto,
                         const RTM_SUB_PROTO_T sub_proto,
                         const uint32_t inst_no,
                         const uint8_t vrf_id);

int8_t
rtm_nh_proto_compare(rtm_nh_proto_t *nh_proto1, rtm_nh_proto_t *nh_proto2);

rtm_error_t
rtm_nh_proto_add(rtm_t *rtm, rtm_nh_proto_t *nh_proto);

rtm_error_t
rtm_nh_proto_del(rtm_t *rtm,
                 const RTM_PROTO_T proto,
                 const RTM_SUB_PROTO_T sub_proto,
                 const uint32_t inst_no,
                 const uint8_t vrf_id);

rtm_nh_proto_t *
rtm_nh_proto_lookup(const rtm_t *rtm, const RTM_PROTO_T proto,
                    const RTM_SUB_PROTO_T sub_proto,
                    const uint32_t inst_no,
                    const uint8_t vrf_id);

/* ----------------------------------------------------------------  */




typedef struct rtm_proto_info_ {

    /* Keys */
    RTM_PROTO_T proto;
    uint32_t instance_no;
    uint8_t vrf_id;
    avltree_node_t proto_glue;
    
} rtm_proto_info_t;

rtm_error_t
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