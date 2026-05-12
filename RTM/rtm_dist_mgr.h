#ifndef __RTM_DIST_MGR__
#define __RTM_DIST_MGR__

#include <stdint.h>
#include <stdbool.h>
#include "../libs/gluethread/glthread.h"
#include "../libs/common/cmn_prefix.h"
#include "../libs/Tree/libtree.h"
#include "../libs/EventDispatcher/event_dispatcher.h"
#include "../libs/BitOp/bitmap.h"

#include "rtm_fib_common.h"
#include "rtm_enums.h"
#include "rtm_nb_integ.h"

typedef struct node_ node_t;
typedef struct rtm_presentation_data_ rtm_presentation_data_t;
typedef struct prefix_lst_ prefix_list_t;
typedef struct rtm_nh_proto_ rtm_nh_proto_t;
typedef struct redist_target_ redist_target_t;

/* Contains all data to select routes and 
    distribute to one and only one client - A Routing protocol  */

#pragma pack(push, 8)

typedef struct rt_redist_route_ {

    uint64_t Cnhidx;  // key
    avltree_node_t nhidx_glue;

    /* Client wants to subscribe to a particular prefix */
    cmn_prefix_t prefix;
    glthread_t rt_pfx_lst_glue;
    
    /* Clients wants route from a particular protocol */
    glthread_t rt_src_lst_glue;

    /* Other Route properties obtained from rtm_proto. Use this 
        to evaulate against filters  */
    rtm_nh_proto_t *nh_proto;

    /* Hook up for advertisement to clients */
    glthread_t redis_glue;

    /* This route has been deleted */
    bool is_deleted;

    uint32_t ref_count;

    /* This track to which clients this route has been  advertised 
        bit 0 - route has not been advertised to client
        bit 1 - route has been advertised to client 
        Be noted : In case the route is deleted (is_deleted = true), 
        and for the client advertisement bit is set to 1, we advertise
        the route to client irrespective of policy decision, and reset it bit to 0.
        This way we ensure that client gets the delete advertisement for the route as well.
    */

    /* Target is identified by using set o 3 bits below */
    struct {

        bitmap_t proto_bitmap;
        bitmap_t vrf_id;
        bitmap_t instance_no;

    } client_advert_tracker;

} rt_redist_route_t;
GLTHREAD_TO_STRUCT(rt_redist_route_redis_glue_to_rt, rt_redist_route_t ,redis_glue);

typedef struct dist_rule_ {

    struct dist_rule_ *next;
    redist_target_t *owning_target;

    /* redistribute connected */
    /* redistribute local */
    /* redistribute static */
    RTM_PROTO_T src_proto;
    RTM_SUB_PROTO_T src_sub_proto;

    /* If CLI do not specify below, borrow it from client
        protocol */
    uint32_t src_instance_no; // default 0
    uint8_t src_vrf_id; // default RTM_DEFAULT_VRF

    /* Filters */
    prefix_list_t *pfx_lst;

    /* Action */
    uint32_t out_cost;
    uint32_t out_tag;
    uint32_t out_community;

} dist_rule_t;

typedef struct rt_advertised_node_ {

    avltree_node_t glue;
    rt_redist_route_t *dist_rt;

} rt_advertised_node_t;

/* The deletion of this object is done in a deferred manner using GC
    so that all routes are synchronized (withdrawn) from this
    target before the target is permanently deleted */
typedef struct redist_target_ {

    /* keys */
    RTM_PROTO_T proto;
    uint32_t instance_no; // default 0
    uint8_t vrf;

    dist_rule_t *rule_list;

    /* list of rt_advert_info_t distributed to this client */
    Fglthread_t client_redis_queue;

    task_t *client_flash_job;

    /* Tree of routes advertised to this target*/
    avltree_t rt_advertised;

    struct redist_target_ *next;

};

static inline bool
redist_route_is_advertised_to_client(rt_redist_route_t *dist_rt, redist_target_t *target) {

    if (bitmap_at(&dist_rt->client_advert_tracker.proto_bitmap, (uint16_t)target->proto) &&
        bitmap_at(&dist_rt->client_advert_tracker.vrf_id, (uint16_t)target->vrf) &&
        bitmap_at(&dist_rt->client_advert_tracker.instance_no, target->instance_no)) {
        
        return true;
    }

    return false;
}

static inline bool 
redist_route_is_advertised_to_client2(rt_redist_route_t *dist_rt, 
    RTM_PROTO_T client_proto, uint8_t vrf_id, uint32_t instance_no) {

    if (bitmap_at(&dist_rt->client_advert_tracker.proto_bitmap, (uint16_t)client_proto) &&
        bitmap_at(&dist_rt->client_advert_tracker.vrf_id, (uint16_t)vrf_id) &&
        bitmap_at(&dist_rt->client_advert_tracker.instance_no, (uint16_t)instance_no)) {
        
        return true;
    }

    return false;
}

void 
rtm_redist_target_record_rt_advertisement 
    (dist_mgr_t *dist_mgr, 
    redist_target_t *target, 
    rt_redist_route_t *dist_rt, bool add);

void 
redist_target_garbage_collect (dist_mgr_t *dist_mgr, 
                                redist_target_t *target);

typedef struct avl_prefix_node_ {

    cmn_prefix_t prefix; // key
    avltree_node_t glue;

    Fglthread_t rt_pfx_lst; 

} avl_prefix_node_t;

typedef struct avl_vrf_node_ {

    uint8_t vrf_no; // key
    uint32_t instance_no; // key
    avltree_node_t glue;

    Fglthread_t rt_src_lst; 

} avl_vrf_node_t;


typedef struct dist_mgr_ {

    node_t *node;
    
    task_t *gc_task;
    task_t *redis_task;

    redist_target_t *target_lst;

    /* Key : rt_redist_route_t->Cnhidx */
    avltree_t nhidx_tree;

    /* Key : Two level Data Structure
        Ist level key : prefix
        2nd level key :  Cnhidx */
    avltree_t route_tree_by_prefix;

    /* Key : Two level Data Structure
        Ist level key : vrf , instance no
        2nd level key : Cnhidx */
    avltree_t route_tree[AFI_MAX][RTM_PROTO_MAX];

    /* Queue to redistribute to clients */
    Fglthread_t redis_queue;
    
    Fglthread_t gc_queue;

} dist_mgr_t;

#pragma pack(pop)

void 
rtm_dist_mgr_init (node_t *node);

/* RTM invoke this API to inform REDIS MANAGER about incremental route updates */
void 
rtm_distribution_manager_update (dist_mgr_t *dist_mgr,
                                 rtm_presentation_data_t *presentation_data);

void 
rtm_dist_mgr_broadcast_dist_routes_to_target (
        dist_mgr_t *dist_mgr, redist_target_t *target);

/* First rule on `target` that permits redistribution of `dist_rt` (source +
 * prefix-list).  When true, optionally sets *rule_out to that rule (for metric,
 * tag, community).  Used by show CLI and internal policy refresh paths. */
bool
rtm_dist_mgr_target_first_permitting_rule(
        redist_target_t *target,
        rt_redist_route_t *dist_rt,
        dist_rule_t **rule_out);

void 
rtm_distribution_manager_show (dist_mgr_t *dist_mgr);

void
rtm_show_dist_mgr_database (dist_mgr_t *dist_mgr);

/* Garbage Collector */
typedef enum DIST_MGR_GC_ {

    DIST_MGR_GC_TYPE_TARGET

} DIST_MGR_GC_TYPE_T;

void 
rtm_dis_mgr_gc (dist_mgr_t *dist_mgr, void *object, DIST_MGR_GC_TYPE_T type);

#endif
