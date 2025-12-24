#ifndef __RTM_NH__
#define __RTM_NH__
#pragma pack(push, 8)

#include <stdint.h>
#include <time.h>
#include "../common/cmn_prefix.h"
#include "../gluethread/glthread.h"
#include "../Tree/libtree.h"
#include "rtm_enums.h"
#include "rtm_error.h"
#include "../common/mpls_lstack.h"
#include "../Interface/InterfaceFwd.h"
#include "../Layer3/SegmentRouting/SRv6/common/srv6_const.h"

typedef struct rtm_ rtm_t;
typedef struct rtm_route_ rtm_route;
typedef struct rtm_nh_proto_ rtm_nh_proto_t;
typedef struct rtm_proto_info_ rtm_proto_info_t;
typedef struct mpls_lstack_ mpls_lstack_t;

#define RTM_DNH_RTM_F_NO_PROPOGATE_UPSTREAM 1
#define RTM_INH_F_RESOLVED_IN_FOREIGN_RTM 2

typedef struct rtm_nh_ {

        /* Unique nexthop index - constant throughout lifetime */
        uint32_t idx;
        uint16_t rtm_flags;
        uint16_t fwd_flags;
        time_t pth_last_update_time;

        /* Owning protocol*/
        RTM_PROTO_T proto;
        /* Owning Sub-protocol */
        RTM_SUB_PROTO_T sub_proto;

        /* Backpointer to the owning route (shared Pointer)*/
        rtm_route* owner_route;
        
        /* Glues*/
        glthread_t route_glue;
        glthread_t src_glue;
        avltree_node_t idx_glue;
        glthread_t advt_glue; // keyed by idx
        
        /* Shared pointer to the protocol info */
        rtm_nh_proto_t *rtm_nh_proto;

        /* Admin distance */
        RTM_AD_T ad;

        /* Metric */
        uint32_t metric;

        /* Action */
        RTM_NH_ACTION_TYPE_T action;

        /* Nexthop prefix */
        cmn_prefix_t prefix;

        /* ifindex if OIF, dont use InterfaceP to make
        it stay a pure C structure */
        uint32_t oif;
        
        /* Backpointer to the owning RTM, used in cross RTM route resolution*/
        rtm_t *rtm;
        
        bool is_indirect;
        /* Data node List of direct nexthops which resolves this INH*/
        Fglthread_t direct_nh_list;
        /* This INH is resolved by this route*/
        rtm_route *resolved_via_route; 
        /* Glue to rtm_route->resolved_lnhs */
        glthread_t route_resolved_list_glue;
        /* Glue to rtm->unresolvable_paths*/
        glthread_t unresolvable_list_glue;
        glthread_t stats_resolved_glue;

        bool is_active;

        /* If this is L3 VPN BGP INH, then it should have
           vpn service label also */
        mpls_label_val_t l3_vpn_label;
        
        /*MPLS  Label Stack*/
        mpls_lstack_t *label_stack;

        /*SRv6 Stack*/
        Srv6_endpcode_t endfn;
        uint8_t n_segment_list;
        cmn_prefix_t *v6segment_lst;

        time_t install_time;
        uint32_t ref_count;
} rtm_nh; 


typedef struct rtm_nh_fwd_info_ {

    uint32_t oif;
    cmn_prefix_t nh_addr;
    uint16_t fwd_flags;

    union {
        
        /*MPLS  Label Stack*/
        struct {
            mpls_lstack_t label_stack;
        } mpls_fwd;

        /*SRv6 Stack*/
        struct {    
            Srv6_endpcode_t endfn;
            uint8_t n_segment_list;
            uint8_t v6segment_lst[MAX_LBL_DEPTH][16];
        } v6_fwd;

    }u;

} rtm_nh_fwd_info_t;


#pragma pack(pop)

GLTHREAD_TO_STRUCT( resolution_list_glue_to_rtm_nh, rtm_nh, route_resolved_list_glue);
GLTHREAD_TO_STRUCT( route_glue_to_rtm_nh, rtm_nh, route_glue);
GLTHREAD_TO_STRUCT( advt_glue_to_rtm_nh, rtm_nh, advt_glue);
GLTHREAD_TO_STRUCT( src_glue_to_rtm_nh, rtm_nh, src_glue);
GLTHREAD_TO_STRUCT( unresolvable_list_glue_to_rtm_nh, rtm_nh, unresolvable_list_glue);
GLTHREAD_TO_STRUCT( stats_resolved_glue_to_rtm_nh, rtm_nh, stats_resolved_glue);

/* Methods */
int8_t rtm_nh_is_equal(rtm_nh *nh1, rtm_nh *nh2);
int8_t rtm_nh_is_equal_in_data_plane(rtm_nh *nh1, rtm_nh *nh2);
int8_t rtm_nh_compare (rtm_nh *nh1, rtm_nh *nh2);
int8_t rtm_nh_compare_by_idx (rtm_nh *nh1, rtm_nh *nh2);
int8_t rtm_nh_forwarding_info_compare (rtm_nh *nh1, rtm_nh *nh2);
void rtm_nh_initialize(rtm_nh *nh);
void rtm_nh_set_active(rtm_t *rtm, rtm_nh *nh);
void rtm_nh_set_inactive(rtm_t *rtm, rtm_nh *nh);
bool rtm_nh_is_resolved (rtm_nh *nh);
void rtm_nh_reference(rtm_nh *nh);
void rtm_nh_dereference(rtm_t *rtm, rtm_nh *nh);
void rtm_flush_inh_direct_nh_set(rtm_t *rtm, rtm_nh *indirect_nh) ;
char* rtm_nh_one_liner_trace (rtm_nh *nh, char *buffer_str, int buff_size);
void rtm_nh_check_and_delete (rtm_t *rtm, rtm_nh *nh) ;

rtm_nh *rtm_nh_lookup_by_idx(rtm_t *rtm, uint32_t idx);
rtm_error_t rtm_nh_add_to_idx_tree(rtm_t *rtm, rtm_nh *nh);
rtm_error_t rtm_nh_remove_from_idx_tree(rtm_t *rtm, rtm_nh *nh);
void rtm_inh_moved_to_resolved_state (rtm_t *rtm, rtm_nh *inh);
void rtm_inh_moved_to_unresolved_state (rtm_t *rtm, rtm_nh *inh);

/* Wrapper to glthread_add_next ()*/
void rtm_nh_glthread_add_next (rtm_nh *nh, 
        glthread_t *curr_glthread, glthread_t *new_glthread);

void rtm_nh_glthread_add_before (rtm_nh *nh, 
        glthread_t *curr_glthread, glthread_t *new_glthread);
        
/* Wrapper over remove_glthread( ) */
void rtm_nh_remove_glthread (rtm_t *rtm, rtm_nh *nh, glthread_t *curr_glthread);

/* Wrapper over Fglthread_add_next()*/
void rtm_nh_fglthread_add_next (rtm_nh *nh, 
        Fglthread_t *head, 
        glthread_t *base_glthread, glthread_t *new_glthread);

/* Wrapper over Fglthread_add_before()*/
void rtm_nh_fglthread_add_before (rtm_nh *nh, 
        Fglthread_t *head, 
        glthread_t *base_glthread, glthread_t *new_glthread);

void
rtm_nh_remove_Fglthread(rtm_t *rtm, rtm_nh *nh, 
                Fglthread_t *head, glthread_t *glthread);

void
rtm_nh_Fglthread_add_last(rtm_nh *nh, 
        Fglthread_t *head, glthread_t *new_glthread);

void 
rtm_nh_avl_insert (rtm_nh *nh, avltree_t *tree, avltree_node_t *avlnode);

void 
rtm_nh_avl_remove (rtm_t *rtm, rtm_nh *nh, 
        avltree_t *tree, avltree_node_t *avlnode);

#endif 
