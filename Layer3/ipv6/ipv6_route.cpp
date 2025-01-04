#include <assert.h>
#include <iostream>
#include "ipv6_route.h"
#include "ipv6_hdrs.h"
#include "ipv6_utils.h"
#include "../../BitOp/bitmap.h"
#include "../../graph.h"
#include "../../Interface/InterfaceFwd.h"
#include "../layer3.h"
#include "../../LinuxMemoryManager/uapi_mm.h"
#include "../../gluethread/glthread.h"
#include "../../Interface/Interface.h"
#include "v6nexthop.h"
#include "ipv6_utils.h"

ipv6_route_t* 
l3rib_v6lookup_lpm ( rt_table_t *v6rt_table, uint8_t (*ipv6_addr)[16]) {

    bitmap_t prefix_bm;
    mtrie_node_t *mnode ;

    bitmap_init(&prefix_bm, 128);
    ipv6_copy_bitmap (ipv6_addr, &prefix_bm);

    mnode = mtrie_longest_prefix_match_search(
                            &v6rt_table->route_list,
                            &prefix_bm);

    bitmap_free_internal(&prefix_bm);
    
    if (!mnode) {
        return NULL;
    }

    assert (mnode->data);
    return (ipv6_route_t *)mnode->data;
}

ipv6_route_t* 
l3rib_v6lookup_lpm2 ( rt_table_t *v6rt_table, ipv6_addr_t *ipv6_addr) {

    bitmap_t prefix_bm;
    mtrie_node_t *mnode ;

    bitmap_init(&prefix_bm, 128);
    ipv6_copy_bitmap (&ipv6_addr->addr, &prefix_bm);

    mnode = mtrie_longest_prefix_match_search(
                            &v6rt_table->route_list,
                            &prefix_bm);

    bitmap_free_internal(&prefix_bm);
    
    if (!mnode) {
        return NULL;
    }

    assert (mnode->data);
    return (ipv6_route_t *)mnode->data;
}

ipv6_route_t* 
l3rib_v6route_lookup_exact_match ( 
                    rt_table_t *v6rt_table, 
                    ipv6_addr_t *prefix, 
                    uint8_t prefix_len) {

    bitmap_t prefix_bm, mask_bm;

    bitmap_init(&prefix_bm, 128);
    bitmap_init(&mask_bm, 128);

    ipv6_copy_bitmap (&prefix->addr, &prefix_bm);

    /* Convert prefix len into ipv6 mask in the form of bitmap */
    for (int i = 0; i < prefix_len; i++) {
        bitmap_set_bit_at(&mask_bm, i);
    }
    bitmap_inverse (&mask_bm, 128);
    
    //cprintf ("Prefix to be exact-matched\n");
    //bitmap_prefix_print (&prefix_bm, &mask_bm, 128);

    mtrie_node_t *node = mtrie_exact_prefix_match_search(
                            &v6rt_table->route_list,
                            &prefix_bm,
                            &mask_bm);

    bitmap_free_internal(&prefix_bm);
    bitmap_free_internal(&mask_bm);
    
    if (!node) {
        return NULL;
    }

    return (ipv6_route_t *)node->data;
}

static inline 
char (*rt_flags_str(uint8_t rt_flags, char (*str)[8])) [8] {

    int index = 0;
    (*str)[index] = '\0';
    if (rt_flags & IPV6_REMOTE_RT) (*str)[index++] = 'R';
    if (rt_flags & IPV6_LOCAL_RT) (*str)[index++] = 'L';
    if (rt_flags & BINDING_SID) (*str)[index++] = 'B';
    (*str)[index] = '\0';
    return str;
}

void 
v6_rt_table_show (rt_table_t *rt_table) {

    char *oif_name;
    char buffer1 [48];
    char rt_flags_arr[8];
    glthread_t *curr = NULL;
    mtrie_node_t *mnode;
    v6nexthop_t *nexthop;
    ipv6_route_t *route = NULL;
    nxthop_proto_id_t nxthop_proto;
    unsigned char uptime_buff[HRS_MIN_SEC_FMT_TIME_LEN];

    cprintf("\nL3 v6 Routing Table\n\n");

    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list.list_head, curr) {

        mnode = list_glue_to_mtrie_node(curr);
        route = (ipv6_route_t *)mnode->data;
        assert(route);
        
        cprintf ("Route : %s/%d\n", inet_ntop6(&route->prefix, buffer1), route->prefix_len);

        FOR_ALL_NXTHOP_PROTO(nxthop_proto) {

            for (int i = 0; i < MAX_NXT_HOPS; i++) {

                if (!route->nexthops[nxthop_proto][i]) continue;

                nexthop = route->nexthops[nxthop_proto][i];

                cprintf (" Proto:%s  F:%s  Metric:%u  ", 
                    proto_name_str(nexthop->proto), 
                    rt_flags_str( nexthop->flags , &rt_flags_arr), nexthop->metric);

                if (!is_ipv6_addr_unspecified (&nexthop->gw.addr)) {
                    cprintf ("Gateway:%s  ", inet_ntop6(&nexthop->gw, buffer1));
                }

                if (nexthop->oif) {
                    cprintf ("OIF : %s  ", nexthop->oif->if_name.c_str());
                }

                cprintf ("Hit Count:%llu  uptime:%s\n", 
                    route->nexthops[nxthop_proto][i]->hit_count,
                    hrs_min_sec_format((unsigned int)difftime(time(NULL),
                                nexthop->install_time), uptime_buff, 
                                HRS_MIN_SEC_FMT_TIME_LEN) );

                switch (nxthop_proto)
                {
                    case proto_nxthop_static:
                    case proto_nxthop_isis:
                    break;
                    case proto_nxthop_srv6:
                    case proto_nxthop_isis_srv6:

                        cprintf ("   SRv6 Fn: %s  ",
                            srv6_end_fn_str(nexthop->u.srv6.endfn));
                        
                        if (nexthop->u.srv6.n_segment_list) {

                            cprintf ("Segment Lst : ");
                            
                            for (int j = 0; j < nexthop->u.srv6.n_segment_list; j++) {
                                cprintf ("%s ", inet_ntop6 (&nexthop->u.srv6.segment_lst[j] , buffer1));
                            }
                        }
                    cprintf ("\n");
                    break;
                }
            }
        }
        cprintf ("\n");

    } ITERATE_GLTHREAD_END(&rt_table->route_list.list_head, curr);
} 

extern v6nexthop_t *
l3_v6route_get_active_nexthop (ipv6_route_t *l3_route) ;

/* Ssync Method of Deleting the IPV6 Routing Table */
void
dp_ipv6_clear_rt_table_sync (rt_table_t *rt_table, uint16_t proto_id){

    int count;
    glthread_t *curr;
    ipv6_route_t *l3_route;
    mtrie_node_t *mnode;
    v6nexthop_t *nexthop;

    nxthop_proto_id_t nh_proto = l3_rt_map_proto_id_to_nxthop_index(proto_id);

    curr = glthread_get_next(&rt_table->route_list.list_head);

    while(curr) {

        mnode = list_glue_to_mtrie_node(curr);

        l3_route = (ipv6_route_t *)(mnode->data);
       assert(l3_route);

        nexthop = l3_v6route_get_active_nexthop (l3_route);

        if (!nexthop) {
            curr = glthread_get_next(curr);
            continue;
        }

        count = v6nh_flush_nexthops(l3_route->nexthops[nh_proto]);
        
        l3_route->nh_count -= count;

        if (l3_route->nh_count) {
            curr = glthread_get_next(curr);
            continue;
        }

       curr = mtrie_node_delete_while_traversal (&rt_table->route_list, mnode);
       //rt_table_add_route_to_notify_list(rt_table, l3_route, RT_DEL_F);
        l3_v6route_dec_ref_count(l3_route);
    }
     
     //rt_table_kick_start_notif_job(rt_table);
}

/* Async Method of Deleting the IPV6 Routing Table */

typedef struct rt_table_flush_meta_data_ {

    rt_table_t *v4_rt_table;
    rt_table_t *v6_rt_table;
    uint16_t proto_id;

} rt_table_flush_meta_data_t;

static void 
dp_ipv6_clear_table_with_preemption (
        node_t *node, 
        rt_table_t *rt_table, uint16_t proto_id);

static void 
rt_v6_table_flush_job (event_dispatcher_t *ev, void *arg, uint32_t arg_size ) {

    rt_table_flush_meta_data_t *rt_table_flush_meta_data = 
        (rt_table_flush_meta_data_t *)arg;

    dp_ipv6_clear_table_with_preemption (
                                        (node_t *)(ev->app_data),
                                        rt_table_flush_meta_data->v6_rt_table, 
                                       rt_table_flush_meta_data->proto_id);

    XFREE (rt_table_flush_meta_data);
}

#define RT_TABLE_PREEMPT_THRESHOLD_COUNT    10

void 
dp_ipv6_clear_table_with_preemption (node_t *node, rt_table_t *rt_table, uint16_t proto_id) {

    int count;
    glthread_t *curr;
    ipv6_route_t *l3_route;
    mtrie_node_t *mnode;
    v6nexthop_t *nexthop;
    uint32_t it_count = 0;

    nxthop_proto_id_t nh_proto = l3_rt_map_proto_id_to_nxthop_index(proto_id);

    curr = glthread_get_next(&rt_table->route_list.list_head);

    while(curr) {

        mnode = list_glue_to_mtrie_node(curr);

        l3_route = (ipv6_route_t *)(mnode->data);
       assert(l3_route);

        nexthop = l3_v6route_get_active_nexthop (l3_route);

        if (!nexthop) {
            curr = glthread_get_next(curr);
            it_count++;
            continue;
        }

        count = v6nh_flush_nexthops(l3_route->nexthops[nh_proto]);
        
        l3_route->nh_count -= count;

        if (l3_route->nh_count) {
            curr = glthread_get_next(curr);
            it_count++;
            continue;
        }

       curr = mtrie_node_delete_while_traversal (&rt_table->route_list, mnode);
       it_count++;
       //rt_table_add_route_to_notify_list(rt_table, l3_route, RT_DEL_F);
        l3_v6route_dec_ref_count(l3_route);

        if (it_count == RT_TABLE_PREEMPT_THRESHOLD_COUNT) {

            /* Preempt and reschedule again*/
            rt_table_flush_meta_data_t *rt_table_flush_meta_data = 
                (rt_table_flush_meta_data_t * ) XCALLOC (0, 1, rt_table_flush_meta_data_t);

            rt_table_flush_meta_data->v6_rt_table = rt_table;
            rt_table_flush_meta_data->proto_id = proto_id;

            task_create_new_job (EV_PURGER(node), 
                    (void *)rt_table_flush_meta_data, 
                    rt_v6_table_flush_job, 
                    TASK_ONE_SHOT, 
                    TASK_PRIORITY_GARBAGE_COLLECTOR );

            return;
        }
    }

     //rt_table_kick_start_notif_job(rt_table);    
}

/* Let us trigger the job to flush the routing table at priority lower than
    pkt processing so that incoming packets dont starve packet procesisng
    in case we are flushing millions of routes.
*/
void
dp_ipv6_clear_rt_table_async (node_t *node, uint16_t proto_id) {

    rt_table_t *v6_rt_table = NODE_V6RT_TABLE (node);

    rt_table_flush_meta_data_t *rt_table_flush_meta_data = 
        (rt_table_flush_meta_data_t * ) XCALLOC (0, 1, rt_table_flush_meta_data_t);

    rt_table_flush_meta_data->v6_rt_table = v6_rt_table;
    rt_table_flush_meta_data->proto_id = proto_id;

    task_create_new_job (EV_DP(node), 
            (void *)rt_table_flush_meta_data, 
            rt_v6_table_flush_job, 
            TASK_ONE_SHOT, 
            TASK_PRIORITY_COMPUTE );
}
