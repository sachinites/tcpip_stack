#ifndef __L2_FWD_OBJECT__
#define __L2_FWD_OBJECT__

#include <stdint.h>
#include "../../../libs/Tree/libtree.h"

typedef struct dp_intf_ dp_intf_t;
typedef struct dp_ctx_ dp_ctx_t;
typedef struct mpls_lstack_ mpls_lstack_t;
typedef struct dp_vrf_ dp_vrf_t;

typedef enum L2_FWD_TYPE_ {

    L2_FWD_PORT,
    L2_FWD_RMAC,
    L2_FWD_FLOODING,
    L2_FWD_MPLS_TUNNEL,
    L2_FWD_SRv6_TUNNEL,
    L2_FWD_VxLAN,
    L2_FWD_STEERING,
    L2_FWD_MAX

} L2_FWD_TYPE_T;


#pragma pack(push, 8)

typedef struct MacFwdObject_ {

    L2_FWD_TYPE_T fwd_type;

    /* Unique ID */
    uint32_t idx;

    /* Non-Comparable fields */
    uint32_t ref_count;
    avltree_node_t glue;
    
    union {

        /* Only port */
        uint32_t dp_intf;

        /* Flooding required two ports - one is vfif and other is vlan/bd port,
           3rd port is recv_intf port which is hidden in packet pvt data */
        struct {

            dp_intf_t *vfif;
            uint32_t  vlan_bd_port;

        }l2_flood;

        /* Only MPLs Label Stack */
        mpls_lstack_t *lbl_stk;

        /* VxLAN */
        struct {

            uint16_t l2vni;
            uint32_t vtep_ip;

        } vxlan;

        /* SRv6 Segment List */
        struct {

            uint8_t seg_lst_cnt;
            uint8_t (*seg_lst)[][16];

        } srv6;

        struct {

            #define STEER_INTO_VRF  0
            #define STEER_INTO_BD   1
            uint8_t steering_type;

            union {

                // Can be VRF or BD 
                uint32_t steered_obj_ifindex;

            } u_steer;

        } steering;

        struct {

            // rmac can be provided bt dp_ctx 
        }rmac;

    } u;

} mac_fwd_object_t;

#pragma pack(pop)


typedef void (*l2_fwding_ptr)(dp_ctx_t *dp_ctx, mac_fwd_object_t *, struct rte_mbuf *);

void 
dp_l2fwd (dp_ctx_t *dp_ctx, mac_fwd_object_t *fwd_obj, struct rte_mbuf *mbuf);

mac_fwd_object_t *
dp_ctx_lookup_mac_fwd_object (avltree_t *tree, mac_fwd_object_t *tmplate);

bool 
dp_ctx_insert_fwd_object (avltree_t *tree, mac_fwd_object_t *fwd_obj);

/* Either mass the dest by caller, or if null, then calloc new object and return */
mac_fwd_object_t *
mac_fwd_object_clone (mac_fwd_object_t *fwd_obj_src, mac_fwd_object_t *fwd_obj_dst);

void 
mac_fwd_object_reference (mac_fwd_object_t *fwd_obj);

void 
mac_fwd_object_dereference (dp_ctx_t *dp_ctx, mac_fwd_object_t *fwd_obj);

void
dp_l2fwd_objects_init (dp_ctx_t *dp_ctx);

/* Build a lookup/insert template from a MAC-table OIF + overlay context. */
void
dp_mac_fwd_object_init_from_oif (dp_ctx_t *dp_ctx,
                                 mac_fwd_object_t *tmpl,
                                 dp_intf_t *oif,
                                 uint32_t remote_dst_ip,
                                 uint16_t vlan_id);

/* Lookup interned object in l2_fwd_obj_tree[]; insert+clone on miss. Takes a ref. */
mac_fwd_object_t *
dp_l2fwd_object_acquire (dp_ctx_t *dp_ctx, mac_fwd_object_t *tmplate);

#endif /* __L2_FWD_OBJECT__ */