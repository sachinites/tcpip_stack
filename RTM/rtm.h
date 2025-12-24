
#ifndef __RTM__
#define __RTM__

#include <stdint.h>
#include "../Tree/libtree.h"
#include "../gluethread/glthread.h"
#include "rtm_enums.h"
#include "rtm_error.h"
#include "../common/cmn_prefix.h"
#include "rtm_priv_api.h"

typedef struct node_ node_t;
typedef struct rtm_nh_ rtm_nh;
typedef struct task_ task_t;
typedef struct mtrie_ mtrie_t;
typedef struct rtm_ppt_db_ rtm_ppt_db_t;

#define RTM_F_INHS_RE_RESOLVE   1

#pragma pack(push, 8)

typedef struct rtm_ {

    /* Keys */
    uint8_t vrf;
    AFI_T afi;
    uint32_t rtm_id;

    uint16_t flags;

    /* RTM name : vrf.inet[6]|mpls.table_id */
    char name[96];

    /* LPM tree of routes in this RTM*/
    mtrie_t *lpm_rt_tree;

    /* Route tree keyed by prefix in this RTM */
    avltree_t route_tree;

    /* Protocol information which came attached with nexthop 
        in the RTM, all fields are keys */
    avltree_t nh_proto_info_tree;

    /* Nexthops indexed by their unique idx */
    avltree_t nhs_by_idx;

    /* Nexthops grouped by their source protocol */
    glthread_t nhs_by_src[RTM_PROTO_MAX];

    /* Protocol information registered in this RTM. Used to
        store protocol subscription and filters */
    avltree_t proto_info_tree[RTM_PROTO_MAX];

    /* Backpointer to owning node*/
    node_t *node; 

    /* Backpointer to the owning RTM, used in cross RTM route resolution*/
    struct rtm_ *rtm;
    
    /* List of Orphan Indirect NHs which have no route to resolve over */
    Fglthread_t unresolvable_paths;
    
    /* List of routes whose resolved INHs are to be propogated upstream in Resolution Graph*/
    Fglthread_t resolved_unpropogated_routes;
    
    /* Job to resolve INHs */
    task_t *nh_resolution_job;

    /* Job to propogate resolved route Active NH upstream in Resolution Graph */
    task_t *rt_resolution_job;

    /* Advertisement Related Fields */
    /* Route trees for presentation. It contains Routes from all Srcs */
    avltree_t ppt_db_route_tree;

    /* List of rtm_presentation_data_t objects, to be advertised to 
        protocols */
    Fglthread_t advt_nhs[RTM_PROTO_MAX];

    /* Queue up rtm_route objects to be Advertised */
    Fglthread_t route_advt_queue;

    /* Job which takes the updated route, compute diff and schedule the 
        actual advertisement throuh advt_job */
    task_t *route_advt_prep_job;
    
    /* Job to advertise the routes to protocols, preemptive */
    task_t *advt_job;

    /* Garbage Collector Job*/
    task_t *gc_job;

    /* Garbage Collector Queue */
    Fglthread_t gc_queue;

    /* For stats */
    struct {

        glthread_t new_resolved_routes;
        glthread_t new_resolved_nhs;
        glthread_t new_unresolved_routes;
        glthread_t new_unresolved_nhs;

    } stats;
    
} rtm_t;

#pragma pack(pop)

rtm_t* rtm_initialize (node_t *node, uint8_t vrf, AFI_T afi, uint32_t rtm_id);
void rtm_stop (rtm_t *rtm);
void rtm_check_and_delete (rtm_t *rtm);
void rtm_log_stats (rtm_t *rtm);
void rtm_clear_stats(rtm_t *rtm);

#endif
