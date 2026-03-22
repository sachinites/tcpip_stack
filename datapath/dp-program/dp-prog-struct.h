#ifndef __DP_PROG_STRUCT__
#define __DP_PROG_STRUCT__

#include <stdint.h>
#include "../../common/mpls_lstack.h"
#include "../../common/cmn_prefix.h"

/* FIX ME : DP including control plane file ... */
#include "../../Layer3/SegmentRouting/SRv6/common/srv6_const.h"

#define CP2DP_MSG_SIZE_MAX  2048

#pragma pack(push, 8)

/* MAC table update msg to MAC_TABLE*/
typedef struct mac_update_msg_ {

    uint8_t mac_addr[6];
    uint16_t vlan_id;
    uint32_t ifindex;
    uint16_t flags;
    uint32_t remote_dst_ip;
    char padding[2];

} mac_update_msg_t;

typedef struct dp_vrf_create_msg_ {

    uint8_t vrf_id;
    char vrf_name[32];
    
} dp_vrf_create_msg_t;

#define DP_VRF_INTF_OP_ADD 1
#define DP_VRF_INTF_OP_DEL 2
typedef struct dp_vrf_intf_update_msg_ {

    uint32_t op_code;
    uint8_t vrf_id;
    uint32_t ifindex;
    
} dp_vrf_intf_update_msg_t;


#define DP_GENERIC_RMAC 1
#define DP_GENERIC_RTR_ID 2

typedef struct dp_generic_msg_ {

    uint8_t opcode;

    union {

        uint8_t mac_addr[6];
        uint32_t rtr_id;

    } u;

} dp_generic_msg_t;




/* ALl interface messages are in separate file */
#include "dp-prog-intf-struct.h"

/*  This structure is used to recv FIB NH info from control plane 
    This structure is clone of fib_nh_fwd_info_t */
typedef struct dp_fib_nh_fwd_info_
{
    uint32_t oif;         /* offset 0, size 16, naturally 8-byte aligned */
    cmn_prefix_t nh_addr; /* offset 16, size 24 */
    uint32_t fwd_flags;   /* offset 40, size 4 */

    union
    {
        /*MPLS  Label Stack*/
        struct
        {
            mpls_lstack_t label_stack;
        } mpls_fwd;

        /*SRv6 Stack*/
        struct
        {
            Srv6_endpcode_t endfn;
            uint8_t n_segment_list;
            uint8_t v6segment_lst[MAX_LBL_DEPTH][16];
        } v6_fwd;

    } u; /* offset 48, now 8-byte aligned */

} dp_fib_nh_fwd_info_t;

typedef struct fib_update_msg_ {

    /* Target FIB VRF ID*/
    uint8_t target_fib_vrf_id;
    /* Target fib AFI*/
    uint8_t target_fib_afi;
    /* Route : ipv4/ipv6/mpls */
    cmn_prefix_t prefix;
    /* Forwarding flags for the nexthop*/
    uint16_t fwd_flags;
    /* Nexthop ID*/
    uint32_t nhidx;
    /* INH ID*/
    uint32_t inhidx;
    /* Forwarding info */
    dp_fib_nh_fwd_info_t fwd_info;

} fib_update_msg_t;

typedef enum DP_COMPONENT_TYPE_ {

    MAC_TABLE,
    PKT_BLOCK,
    FIB_TABLE,
    INTF_TABLE,
    VRF_TABLE,
    DP_GENERICS

} DP_COMPONENT_TYPE_T;

typedef enum DP_OPR_TYPE_ {

    DP_CREATE,
    DP_DEL,
    DP_UPDATE,
    DP_READ,
    DP_L3_NORTHBOUND_IN
    
} DP_OPR_TYPE_T;

typedef struct dp_msg_ {

    uint8_t data[CP2DP_MSG_SIZE_MAX];
    DP_COMPONENT_TYPE_T component_type;
    DP_OPR_TYPE_T opr_type;
    uint32_t data_size;
    uint16_t flags;
    uint8_t vrf_id;
    char padding[1];
    
} dp_msg_t;

#pragma pack(pop)

#endif 