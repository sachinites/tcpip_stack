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
    memcpy (prefix_bm.bits, *ipv6_addr, 16);

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
    memcpy (prefix_bm.bits, ipv6_addr->addr, 16);

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

    memcpy (prefix_bm.bits, prefix->addr, 16);

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

void 
v6_rt_table_show (rt_table_t *rt_table) {

    char buffer1 [48];
    char *oif_name;
    glthread_t *curr = NULL;
    mtrie_node_t *mnode;
    v6nexthop_t *nexthop;
    ipv6_route_t *route = NULL;
    nxthop_proto_id_t nxthop_proto;

    cprintf("\nL3 v6 Routing Table\n\n");

    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list.list_head, curr) {

        mnode = list_glue_to_mtrie_node(curr);
        route = (ipv6_route_t *)mnode->data;
        assert(route);
        
        cprintf ("Route : %s/%d\n", inet_ntop6(&route->prefix, buffer1), route->prefix_len);

        FOR_ALL_NXTHOP_PROTO(nxthop_proto) {

            for (int i = 0; i < MAX_NXT_HOPS; i++) {

                if (!route->nexthops[nxthop_proto][i])
                    continue;

                nexthop = route->nexthops[nxthop_proto][i];

                cprintf (" Proto : %s\n",  proto_name_str(nexthop->proto));
                cprintf (" Metric : %u\n",  nexthop->metric);

                switch (nxthop_proto)
                {
                    case proto_nxthop_static:
                    case proto_nxthop_isis:
                    break;
                    case proto_nxthop_srv6:

                        cprintf (" SRv6 End Function : %s (%s), flags : %d\n", 
                            end_fn_str(nexthop->u.srv6.endfn), 
                            flavor_str(nexthop->u.srv6.srv6_flavors),
                            nexthop->u.srv6.flags);
                        
                        if (nexthop->u.srv6.n_segment_list) {

                            cprintf (" Segment Lst : ");
                            
                            for (int j = 0; j < nexthop->u.srv6.n_segment_list; j++) {
                                cprintf ("%s ", inet_ntop6 (&nexthop->u.srv6.segment_lst[j] , buffer1));
                            }

                            cprintf ("\n");
                        }
                        
                        break;
                }

                if (!is_ipv6_addr_unspecified (&nexthop->gw.addr)) {
                    cprintf (" Gateway : %s\n", inet_ntop6(&nexthop->gw, buffer1));
                }

                if (nexthop->oif) {
                    cprintf (" OIF : %s\n", nexthop->oif->if_name.c_str());
                }

                cprintf (" Hit Count : %llu\n\n", route->nexthops[nxthop_proto][i]->hit_count);
            }
        }
        
    } ITERATE_GLTHREAD_END(&rt_table->route_list.list_head, curr);
    
} 

extern v6nexthop_t *
l3_v6route_get_active_nexthop (ipv6_route_t *l3_route) ;

void
dp_ipv6_clear_table (rt_table_t *rt_table, uint16_t proto_id){

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
