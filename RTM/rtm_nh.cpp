#include <memory.h>
#include <stdlib.h>
#include <assert.h>
#include <atomic>
#include "../Tree/libtree.h"
#include "rtm_nh.h"
#include "rtm_route.h"
#include "rtm_proto.h"
#include "rtm_resolution.h"
#include "rtm_fib_interface.h"
#include "rtm_priv_api.h"
#include "../router_init.h"
#include "../tcp_ip_trace.h"
#include "../Tracer/tracer.h"
#include "rtm_presentation.h"
#include "rtm_gc.h"
#include "../common/mpls_lstack.h"

/* Thread-safe atomic counter for nexthop ID generation */
static std::atomic<uint32_t> rtm_nh_id_counter(1);

/* Generate a unique nexthop ID atomically */
static uint32_t rtm_nh_generate_id(void) {
    return rtm_nh_id_counter.fetch_add(1, std::memory_order_relaxed);
}

static void rtm_nh_goes_active (rtm_t *rtm, rtm_nh *nh);
static void rtm_nh_goes_inactive (rtm_t *rtm, rtm_nh *nh);

extern void rtm_presentation_layer_route_add (rtm_t *rtm, rtm_nh *nh);

static void
rtm_nh_release_all_resources(rtm_t *rtm, rtm_nh *nh)
{
    if (nh->label_stack)
    {
        XFREE(nh->label_stack);
        nh->label_stack = NULL;
    }

    if (nh->rtm_nh_proto)
    {
        rtm_nh_proto_dereference(rtm, nh->rtm_nh_proto);
        nh->rtm_nh_proto = NULL;
    }

    nh->oif = 0;

    rtm_route_dereference (rtm, nh->owner_route);
    nh->owner_route = NULL;
}

void 
rtm_nh_check_and_delete (rtm_t *rtm, rtm_nh *nh) {

    char gw_str[48];
    rtm_nh_release_all_resources(rtm, nh);
    assert(nh->owner_route == NULL);
    assert(!IS_QUEUED_UP_IN_THREAD(&nh->route_glue));
    assert(!IS_QUEUED_UP_IN_THREAD(&nh->route_resolved_list_glue));
    assert(!IS_QUEUED_UP_IN_THREAD(&nh->unresolvable_list_glue));
    assert(!IS_QUEUED_UP_IN_THREAD(&nh->src_glue));
    assert(!avltree_node_is_inuse(&rtm->nhs_by_idx, &nh->idx_glue));
    assert(!IS_QUEUED_UP_IN_THREAD(&nh->advt_glue));
    assert (nh->rtm_nh_proto == NULL);
    assert (nh->oif == 0);
    assert (nh->label_stack == NULL);
    assert (nh->ref_count == 0);
    assert (nh->v6segment_lst == NULL);
    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : NH %s(idx=%u) destroyed NH\n",
        rtm->name,
        rtm_format_nexthop(&nh->prefix, gw_str, sizeof(gw_str)),
        nh->idx);    
    XFREE (nh);
}

void 
rtm_nh_reference(rtm_nh *nh) {
    
    nh->ref_count++;
}

void 
rtm_nh_dereference(rtm_t *rtm, rtm_nh *nh) {
        
    nh->ref_count--;

    if (nh->ref_count == 0) {
        rtm_gc_nh (rtm, nh);
    }
}

/* Wrapper for compare function with exact signature from header */
int8_t 
rtm_nh_is_equal(rtm_nh* nh1, rtm_nh* nh2) {
    
    if (!nh1 || !nh2) {
        return -1;
    }
    
    // Compare protocol
    if (nh1->proto != nh2->proto) {
        return (nh1->proto < nh2->proto) ? -1 : 1;
    }
    
    // Compare sub-protocol
    if (nh1->sub_proto != nh2->sub_proto) {
        return (nh1->sub_proto < nh2->sub_proto) ? -1 : 1;
    }
        // Compare admin distance
    if (nh1->ad != nh2->ad) {
        return (nh1->ad < nh2->ad) ? -1 : 1;
    }

    // Compare metric
    if (nh1->metric != nh2->metric) {
        return (nh1->metric < nh2->metric) ? -1 : 1;
    }

    // Compare action
    if (nh1->action != nh2->action) {
        return (nh1->action < nh2->action) ? -1 : 1;
    }
    

    // Compare outgoing interface
    if (nh1->oif != nh2->oif) {
        return (nh1->oif < nh2->oif) ? -1 : 1;
    }
    
    // Compare prefix
    int prefix_cmp = cmn_prefix_compare(&nh1->prefix, &nh2->prefix);
    if (prefix_cmp != 0) {
        return prefix_cmp;
    }

    int8_t rc = rtm_nh_proto_is_equal (nh1->rtm_nh_proto, nh2->rtm_nh_proto);
    if (rc != 0) return rc;

    if (!nh1->label_stack && nh2->label_stack) {
        return 1;
    }
    if (nh1->label_stack && !nh2->label_stack) {
        return -1;
    }

    if (!nh1->label_stack && !nh2->label_stack) {
        return 0;
    }

    return memcmp (nh1->label_stack, nh2->label_stack, sizeof(*nh1->label_stack));
}

int8_t 
rtm_nh_is_equal_in_data_plane(rtm_nh *nh1, rtm_nh *nh2) {

    if (nh1->action != nh2->action) {
        return (nh1->action < nh2->action) ? -1 : 1;
    }

    // Compare outgoing interface
    if (nh1->oif != nh2->oif) {
        return (nh1->oif < nh2->oif) ? -1 : 1;
    }
    
    // Compare prefix
    int prefix_cmp = cmn_prefix_compare(&nh1->prefix, &nh2->prefix);
    if (prefix_cmp != 0) {
        return prefix_cmp;
    }

    if (!nh1->label_stack && nh2->label_stack) {
        return 1;
    }
    if (nh1->label_stack && !nh2->label_stack) {
        return -1;
    }

    if (!nh1->label_stack && !nh2->label_stack) {
        return 0;
    }

    if (!mpls_lstack_compare (nh1->label_stack, nh2->label_stack)) return -1;

    return 0;
    // Copare SRv6 .. Later ...
}

/* Insert nexthop in route path list as per below rules : 
    1. lowest admin distance wins
    2. if admin distance is same, lowest Action wins
    3. if action is same lowest cost wins
    4. If both paths are BGP, then compare BGP attributes ( ToDO )
    5. if cost is same, then tie
*/
int8_t 
rtm_nh_compare (rtm_nh *nh1, rtm_nh *nh2) {

    // NULL checks
    if (!nh1 && !nh2) return 0;
    if (!nh1) return 1;  // nh2 wins
    if (!nh2) return -1; // nh1 wins
    
    // Rule 1: Lowest admin distance wins
    if (nh1->ad != nh2->ad) {
        return (nh1->ad < nh2->ad) ? -1 : 1;
    }
    
    // Rule 2: If admin distance is same, lowest Action wins
    // (Note: enum order matters - most preferred action first)
    if (nh1->action != nh2->action) {
        return (nh1->action < nh2->action) ? -1 : 1;
    }
    
    // Rule 3: If action is same, lowest cost (metric) wins
    if (nh1->metric != nh2->metric) {
        return (nh1->metric < nh2->metric) ? -1 : 1;
    }
    
    // Rule 4: If both paths are BGP, then compare BGP attributes (TODO)
    // TODO: Implement BGP attribute comparison
    
    // Rule 5: If cost is same, then tie
    return 0;
}

int
rtm_nh_compare_by_idx (const avltree_node_t *node1, const avltree_node_t *node2) {

    rtm_nh *nh1 = avltree_container_of(node1, rtm_nh, idx_glue);
    rtm_nh *nh2 = avltree_container_of(node2, rtm_nh, idx_glue);

    if (nh1->idx < nh2->idx) return -1;
    if (nh1->idx > nh2->idx) return 1;
    return 0;
}

/* Cpmpare only forwarding behavior of the nexthop*/
int8_t 
rtm_nh_forwarding_info_compare (rtm_nh *nh1, rtm_nh *nh2) {

    int8_t rc = cmn_prefix_compare (&nh1->prefix, &nh2->prefix);
    if (!rc) return rc;
    if (nh1->oif  < nh2->oif) return -1;
    if (nh1->oif > nh2->oif) return 1; 

    if (!mpls_lstack_compare (nh1->label_stack, nh2->label_stack)) return -1;

     // Add more attributes here ...
    return rc;
}

/* Initialize a nexthop structure */
void 
rtm_nh_initialize(rtm_nh* nh) {
    
    nh->idx = rtm_nh_generate_id();
    nh->rtm_flags = 0;
    nh->fwd_flags = 0;
    nh->pth_last_update_time = time(NULL);
    nh->owner_route = NULL;
    
    init_glthread(&nh->route_glue);
    init_glthread(&nh->src_glue);
    init_glthread(&nh->route_resolved_list_glue);
    init_glthread(&nh->unresolvable_list_glue);
    avltree_node_init(&nh->idx_glue);
    init_glthread(&nh->advt_glue);
    
    nh->rtm_nh_proto = NULL;
    nh->ad = RTM_ADMIN_DIST_UNKNOWN;
    nh->metric = 0;
    nh->action = RTM_NH_ACTION_FORWARD;
    
    memset(&nh->prefix, 0, sizeof(cmn_prefix_t));
    nh->oif = 0;
    
    nh->is_indirect = false;
    nh->is_active = false;
    
    nh->label_stack = NULL;
    nh->install_time = time(NULL);
    nh->ref_count = 0;
}


void 
rtm_nh_set_active(rtm_t *rtm, rtm_nh *nh) {

    char gw_str[128];
    char prefix_str[48];

    assert (!nh->is_active);

    tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : Route : %s : Setting NH Active, NH=%s Is_indirect=%s Resolved=%s\n",
            rtm->name,
            rtm_format_prefix(&nh->owner_route->prefix, prefix_str, sizeof(prefix_str)),
            rtm_nh_one_liner_trace(nh, gw_str, sizeof(gw_str)),
            nh->is_indirect ? "Yes" : "No",
            rtm_nh_is_resolved(nh) ? "Yes" : "No");

    nh->is_active = true;

    /* If this is indirect NH, then submit it for resolution again, There can be more INHs 
        being set to active at this point, so defer the work of updating Routes upstream in 
        resolution graph */
    if (nh->is_indirect) {
        
        assert (!rtm_nh_is_resolved (nh));
        assert (nh->resolved_via_route == NULL);
        assert (!IS_QUEUED_UP_IN_THREAD(&nh->route_resolved_list_glue));
        assert (!nh->resolved_via_route);
        assert (!IS_QUEUED_UP_IN_THREAD(&nh->unresolvable_list_glue));
        assert (Fglthread_list_is_empty (&nh->direct_nh_list));

        /* Check if this nexthop can be resolved */
        rtm_route *route = rtm_get_resolver_route(rtm, nh);
        
        if (!route) {

            /* INH is not resolvable */
            tracer(rtm->node->cptr, DRTM,
                "RTM[%s] : Route : %s : INH %s is still unresolvable, queuing for resolution\n",
                rtm->name,
                rtm_format_prefix(&nh->owner_route->prefix, prefix_str, sizeof(prefix_str)),
                rtm_nh_one_liner_trace(nh, gw_str, sizeof(gw_str)));

            rtm_nh_Fglthread_add_last (nh, 
                                &rtm->unresolvable_paths, 
                                &nh->unresolvable_list_glue); 

            rtm_schedule_nh_resolution_worker(rtm);
            return;
        }

        /* The INH is resolvale , borrow its DNHs from the route's active set */
        rtm_copy_route_active_nhs_to_inh_direct_nh_set(rtm, route, nh);

        /* Establish the linkage with downstream router in resolution graph*/
        nh->resolved_via_route = route;
        rtm_route_reference (route);
        rtm_nh_Fglthread_add_last (nh, &route->resolved_lnhs, 
            &nh->route_resolved_list_glue);
        rtm_inh_moved_to_resolved_state(rtm, nh);

        /* The caller must call rtm_resolve_routes_recursively ( ) to propogate resolution
            effect upstream in resolution graph*/
    }
    else {
        /* Handled by caller by calling rtm_resolve_routes_recursively ( )*/
    }

    rtm_schedule_route_advertisement (nh->rtm, nh->owner_route);
}

void 
rtm_nh_set_inactive(rtm_t *rtm, rtm_nh *nh) {

    char prefix_str[48];
    char gw_str[48];

    assert(nh->is_active);
    
    tracer(rtm->node->cptr, DRTM_DET,
            "RTM[%s] : Setting NH inactive for route %s, NH=%s Proto=%s\n",
            rtm->name,
            rtm_format_prefix(&nh->owner_route->prefix, prefix_str, sizeof(prefix_str)),
            rtm_format_nexthop(&nh->prefix, gw_str, sizeof(gw_str)),
            rtm_proto_to_string(nh->proto));
    
    nh->is_active = false;

    /* The INH is switched from Active to Inactive state , Possible Cases : 
        1. It is already awaiting resolution , Action : Dont bother to resolve it anymore
        2. It is resolved, Action : Make it unresolved and update upstream Routes in resolution graph
    */
    if (nh->is_indirect) {

        rtm_resolution_nh_withdraw(rtm, nh);
    }
    else {
        /* Handled by caller by calling rtm_resolve_routes_recursively ( )*/
    }

    rtm_schedule_route_advertisement (nh->rtm, nh->owner_route);
    
    tracer(rtm->node->cptr, DRTM,
            "RTM[%s] : NH deactivated and removed from FIB for route %s\n",
            rtm->name,
            rtm_format_prefix(&nh->owner_route->prefix, prefix_str, sizeof(prefix_str)));
}

void
rtm_flush_inh_direct_nh_set(
    rtm_t *rtm, rtm_nh *indirect_nh) {
    
    glthread_t *curr_glue;
    glthread_t *next_glue;
    glthread_data_node_t *data_node;
    rtm_nh *nh;
    char gw_str[128];
    char nh_str[128];

    tracer(rtm->node->cptr, DRTM,
        "RTM[%s] : Flushing direct NH set of INH %s\n",
        rtm->name,
        rtm_nh_one_liner_trace(indirect_nh, gw_str, sizeof(gw_str)));

    ITERATE_GLTHREAD_BEGIN(&indirect_nh->direct_nh_list.head, curr_glue) {

        data_node = glue_to_glthread_data_node(curr_glue);
        nh = (rtm_nh *)data_node->data;
        rtm_nh_remove_Fglthread (rtm, nh, 
            &indirect_nh->direct_nh_list, curr_glue);

        tracer(rtm->node->cptr, DRTM_DET,
            "RTM[%s] : INH %s removing direct NH %s from its direct NH set\n",
            rtm->name,
            rtm_nh_one_liner_trace(indirect_nh, gw_str, sizeof(gw_str)),
            rtm_nh_one_liner_trace(nh, nh_str, sizeof(nh_str)));

        XFREE (data_node);

    } ITERATE_GLTHREAD_END(&indirect_nh->direct_nh_list.head, curr_glue);

}

bool rtm_nh_is_resolved (rtm_nh *nh) {

    if (!nh->is_indirect) return true;
    return !(Fglthread_list_is_empty(&nh->direct_nh_list));
}

void 
rtm_inh_moved_to_resolved_state (rtm_t *rtm, rtm_nh *inh) {

    char route_str[48];
    char inh_str[128];
    char route_resolver_str[48];

    tracer (rtm->node->cptr, DRTM,
        "RTM[%s] : Route : %s : INH %s moved to resolved state, Resolved by %s\n",
        rtm->name,
        rtm_format_prefix(&inh->owner_route->prefix, route_str, sizeof(route_str)),
        rtm_nh_one_liner_trace(inh, inh_str, sizeof(inh_str)),
        rtm_format_prefix(&inh->resolved_via_route->prefix, 
            route_resolver_str, sizeof(route_resolver_str)));

    inh->owner_route->resolved_inh_count++;

    if (inh->owner_route->resolved_inh_count == 1) {
        rtm_route_moved_to_resolved_state (rtm, inh->owner_route);
    }

    if (IS_QUEUED_UP_IN_THREAD(&inh->stats_resolved_glue)) {
        remove_glthread(&inh->stats_resolved_glue);
        rtm_nh_dereference(rtm, inh);
    }

    glthread_add_next(&rtm->stats.new_resolved_nhs, &inh->stats_resolved_glue);
    rtm_nh_reference(inh);
}

void 
rtm_inh_moved_to_unresolved_state (rtm_t *rtm, rtm_nh *inh) {

    char route_str[48];
    char inh_str[128];

    tracer (rtm->node->cptr, DRTM,
        "RTM[%s] : Route : %s : INH %s moved to UnResolved state\n",
        rtm->name,
        rtm_format_prefix(&inh->owner_route->prefix, route_str, sizeof(route_str)),
        rtm_nh_one_liner_trace(inh, inh_str, sizeof(inh_str)));

        assert (inh->owner_route->resolved_inh_count > 0);
        inh->owner_route->resolved_inh_count--;

        if (inh->owner_route->resolved_inh_count == 0) {
            rtm_route_moved_to_unresolved_state (rtm, inh->owner_route);
        }

    if (IS_QUEUED_UP_IN_THREAD(&inh->stats_resolved_glue)) {
        remove_glthread(&inh->stats_resolved_glue);
        rtm_nh_dereference(rtm, inh);
    }

    glthread_add_next(&rtm->stats.new_unresolved_nhs, &inh->stats_resolved_glue);
    rtm_nh_reference(inh);
}

void rtm_nh_glthread_add_next (
    rtm_nh *nh, glthread_t *curr_glthread, glthread_t *new_glthread){
    
    assert (!IS_QUEUED_UP_IN_THREAD(new_glthread));
    glthread_add_next (curr_glthread, new_glthread);
    rtm_nh_reference (nh);
    
    /* Note: Cannot trace here as we don't have RTM context */
}

void rtm_nh_glthread_add_before (
    rtm_nh *nh, glthread_t *curr_glthread, glthread_t *new_glthread){
    
    assert (!IS_QUEUED_UP_IN_THREAD(new_glthread));
    glthread_add_before (curr_glthread, new_glthread);
    rtm_nh_reference (nh);
}

void rtm_nh_remove_glthread (rtm_t *rtm, rtm_nh *nh, glthread_t *curr_glthread){

    assert (IS_QUEUED_UP_IN_THREAD(curr_glthread));
    
    char nh_str[128];
    tracer(rtm->node->cptr, DRTM_DET,
        "RTM[%s] : NH %s removing from glthread\n",
        rtm->name,
        rtm_nh_one_liner_trace(nh, nh_str, sizeof(nh_str)));
    
    remove_glthread (curr_glthread);
    rtm_nh_dereference (rtm, nh);
}

void rtm_nh_fglthread_add_next (rtm_nh *nh, 
        Fglthread_t *head, 
        glthread_t *base_glthread, glthread_t *new_glthread) {

    assert (!IS_QUEUED_UP_IN_THREAD(new_glthread));
    Fglthread_add_next (head, base_glthread, new_glthread);
    rtm_nh_reference (nh);
}

void rtm_nh_fglthread_add_before (rtm_nh *nh, 
        Fglthread_t *head, 
        glthread_t *base_glthread, glthread_t *new_glthread) {

    assert (!IS_QUEUED_UP_IN_THREAD(new_glthread));
    Fglthread_add_before (head, base_glthread, new_glthread);
    rtm_nh_reference (nh);
}

void
rtm_nh_remove_Fglthread(rtm_t *rtm, rtm_nh *nh, 
                Fglthread_t *head, glthread_t *glthread){

    assert (IS_QUEUED_UP_IN_THREAD(glthread));
    remove_Fglthread (head, glthread);
    rtm_nh_dereference (rtm, nh);
}

void
rtm_nh_Fglthread_add_last(rtm_nh *nh, 
        Fglthread_t *head, glthread_t *new_glthread) {


    assert (!IS_QUEUED_UP_IN_THREAD(new_glthread));
    Fglthread_add_last (head, new_glthread);
    rtm_nh_reference (nh);
}

void 
rtm_nh_avl_insert (rtm_nh *nh, avltree_t *tree, avltree_node_t *avlnode){

    assert (!avltree_node_is_inuse(tree, avlnode));
    assert (!avltree_insert(avlnode, tree));
    rtm_nh_reference (nh);
    
    /* Note: Cannot trace here as we don't have RTM context */
}

void 
rtm_nh_avl_remove (rtm_t *rtm, rtm_nh *nh, 
    avltree_t *tree, avltree_node_t *avlnode){

    assert (avltree_node_is_inuse(tree, avlnode));
    avltree_strict_remove(avlnode, tree); 
    rtm_nh_dereference (rtm, nh);
}

char *
rtm_nh_one_liner_trace (rtm_nh *nh, char *buffer_str, int buff_size) {

    char nh_addr_str[48];
    rtm_format_nexthop(&nh->prefix, nh_addr_str, sizeof(nh_addr_str));

    snprintf(buffer_str, buff_size, 
             "NH[idx=%u, %s, %s]",
             nh->idx,
             nh_addr_str,
             rtm_proto_to_string(nh->proto));

    return buffer_str;
}

rtm_nh *
rtm_nh_lookup_by_idx(rtm_t *rtm, uint32_t idx) {

    rtm_nh nh_template;

    rtm_nh_initialize (&nh_template);
    nh_template.idx = idx;

    avltree_node_t *node = avltree_lookup(&nh_template.idx_glue, &rtm->nhs_by_idx);
    if (!node) return NULL;

    return avltree_container_of(node, rtm_nh, idx_glue);
}

rtm_error_t 
rtm_nh_add_to_idx_tree(rtm_t *rtm, rtm_nh *nh) {

    rtm_nh_avl_insert(nh, &rtm->nhs_by_idx, &nh->idx_glue);
    return RTM_SUCCESS;
}

rtm_error_t 
rtm_nh_remove_from_idx_tree(rtm_t *rtm, rtm_nh *nh) {

    rtm_nh_avl_remove(rtm, nh, &rtm->nhs_by_idx, &nh->idx_glue);
    return RTM_SUCCESS;
}
