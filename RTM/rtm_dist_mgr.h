#ifndef __RTM_DIST_MGR__
#define __RTM_DIST_MGR__

#include <stdint.h>
#include "../libs/gluethread/glthread.h"
#include "../libs/common/cmn_prefix.h"
#include "../libs/Tree/libtree.h"
#include "../libs/EventDispatcher/event_dispatcher.h"

#include "rtm_fib_common.h"
#include "rtm_enums.h"
#include "rtm_nb_integ.h"

typedef struct node_ node_t;
typedef struct rtm_presentation_data_ rtm_presentation_data_t;
typedef struct prefix_lst_ prefix_list_t;
typedef struct rtm_nh_proto_ rtm_nh_proto_t;

/* Contains all data to select routes and 
    distribute to one and only one client - A Routing protocol  */

#pragma pack(push, 8)

typedef struct rt_redist_route_key_ {

    uint8_t vrf_id;
    uint32_t instance_no;

} rt_redist_route_key_t;


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

    bool is_deleted;

    uint32_t ref_count;

} rt_redist_route_t;
GLTHREAD_TO_STRUCT(rt_redist_route_redis_glue_to_rt, rt_redist_route_t ,redis_glue);


typedef struct dist_rule_ {

    struct dist_rule_ *next;

    /* redistribute connected */
    /* redistribute local */
    /* redistribute static */
    RTM_PROTO_T src_proto;
    RTM_SUB_PROTO_T src_sub_proto;

    /* redistribute ospf 1 */
    /* redistribute bgp 65501 */
    uint8_t src_instance_no; // default 0

    /* Filters */
    prefix_list_t *pfx_lst;

    /* Action */
    uint32_t out_cost;
    uint32_t out_tag;
    uint32_t out_community;

} dist_rule_t;


typedef struct redist_target_ {

    /* keys */
    RTM_PROTO_T dst_proto;
    uint32_t dst_instance_no; // default 0
    uint8_t dst_vrf;
    uint32_t target_handle;

    dist_rule_t *rule_list;

    /* client Notification callback */
    void (*redis_cbk)(node_t *, rt_advert_info_t  *);

    /* list of rt_advert_info_t distributed to this client */
    Fglthread_t client_redis_queue;

    task_t *client_flash_job;

    struct redist_target_ *next;

} redist_target_t;

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

    /* Garbage Collector Queue */
    Fglthread_t gc_queue; // reuse rt_redist_route_t->advert_thread_glue;

} dist_mgr_t;

#pragma pack(pop)

void 
rtm_dist_mgr_init (node_t *node);

/* An Explicit API to inform DIST MGR about route delete */
void 
rtm_distribution_manager_route_delete (dist_mgr_t *dist_mgr, cmn_prefix_t *route);

/* RTM invoke this API to inform REDIS MANAGER about incremental route updates */
void 
rtm_distribution_manager_update (dist_mgr_t *dist_mgr,
                                 rtm_presentation_data_t *presentation_data);

/* REDIS MGR pushed routes in bulk to the particular target client */
void 
rtm_distribution_manager_flash_routes_to_target (
        dist_mgr_t *dist_mgr, redist_target_t *target);

/* Client APIs */
uint32_t
rtm_distribution_manager_client_register (
        dist_mgr_t *dist_mgr,
        RTM_PROTO_T target_proto, 
        uint8_t target_instance_no, 
        uint16_t target_vrf, 
        void (*redis_cbk)(node_t *, rt_advert_info_t  *));

void
rtm_distribution_manager_client_unregister(
        dist_mgr_t *dist_mgr, 
        uint32_t target_handle);

void 
rtm_distribution_manager_client_update_rule(
        dist_mgr_t *dist_mgr, 
        uint32_t target_handle, dist_rule_t *rule, bool add);

void 
rtm_distribution_manager_flash_request(
        dist_mgr_t *dist_mgr, uint32_t target_handle);

void 
rtm_distribution_manager_show (dist_mgr_t *dist_mgr);

void
rtm_show_dist_mgr_database (dist_mgr_t *dist_mgr);

#endif
