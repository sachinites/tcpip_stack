#include <assert.h>
#include <iostream>
#include "ipv6_route.h"
#include "ipv6_hdrs.h"
#include "ipv6_utils.h"
#include "../BitOp/bitmap.h"
#include "../graph.h"
#include "../Interface/InterfaceFwd.h"
#include "../Layer3/layer3.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../gluethread/glthread.h"
#include "../Interface/Interface.h"
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


 bool 
 ipv6_route_install (node_t *node, 
                                ipv6_addr_t *prefix,
                                uint8_t prefix_len,
                                uint8_t rt_flags,
                                ipv6_addr_t *gw,
                                Interface* oif,   // can be NULL
                                uint32_t spf_metric,
                                Srv6_endpcode_t endfn,
                                uint8_t srv6_flavor,
                                uint16_t proto ) {


    bool new_route = false;
    v6nexthop_t *nexthop = NULL;
    
    rt_table_t *rt_table = NODE_V6RT_TABLE(node);

    nxthop_proto_id_t proto_id = l3_rt_map_proto_id_to_nxthop_index (proto);

    if (proto_id == proto_nxthop_max) {
        cprintf ("Error : Invalid proto_id\n");
        return false;
    }

    ipv6_route_t *route = l3rib_v6route_lookup_exact_match (
                                NODE_V6RT_TABLE(node), prefix, prefix_len);
    
    if (!route) {

        route = (ipv6_route_t *)calloc (1, sizeof (ipv6_route_t));
        memcpy (route->prefix.addr, prefix->addr, 16);
        route->is_direct = true;
        route->prefix_len = prefix_len;
        route->nh_count = 0;
        route->install_time = time(NULL);
        route->rt_ref_count = 0;
        route->nxthop_idx = 0;
        init_glthread(&route->notif_glue);
        init_glthread(&route->flash_glue);
        new_route = true;
    }

    if (!new_route && route->nh_count ==MAX_NXT_HOPS) {
        cprintf ("Max nexthops reached for this route\n");
        return false;
    }

    if (oif || (proto == PROTO_SRv6)) {

        nexthop = new v6nexthop_t;
        nexthop->ifindex = oif ? oif->ifindex : 0;
        if (gw)
            memcpy(nexthop->gw.addr, gw->addr, 16);
        nexthop->proto = proto;
        nexthop->oif = oif ? oif->GetSharedPtr() : nullptr;
        nexthop->ref_count = 0;
        nexthop->hit_count = 0;
        route->is_direct = false;

        if (proto == PROTO_SRv6)
        {
            nexthop->u.srv6.metric = spf_metric;
            nexthop->u.srv6.endfn = endfn;
            nexthop->u.srv6.srv6_flavors = srv6_flavor;
            nexthop->u.srv6.flags = rt_flags;
        }
    }

    /* Handle direct routes */
    if (new_route && !nexthop) {
        return ipv6_add_route_to_rib  (rt_table, route);
    }

    int index;
    int res = v6nh_is_nexthop_exist_in_nh_array (
            route->nexthops[proto_id], nexthop, &index) ;

    switch (res)
    {
    case 0:
        cprintf("Error : Nexthop already exists\n");
        delete nexthop;
        return false;
    case -1:
        v6nh_insert_new_nexthop_nh_array(
            route->nexthops[proto_id], nexthop);
        route->nh_count++;
        break;
    case 1:
        /* Replace the nexthop*/
        delete route->nexthops[proto_id][index];
        route->nexthops[proto_id][index] = nullptr;
        route->nexthops[proto_id][index] = nexthop;
        break;
    }

    if (!new_route) return true;
    return ipv6_add_route_to_rib  (rt_table, route);
}

 bool 
 ipv6_route_delete (node_t *node, 
                                ipv6_addr_t *prefix,
                                uint8_t prefix_len,
                                ipv6_addr_t *gw,
                                Interface* oif, 
                                uint16_t proto_id) {

    int index;
    rt_table_t *rt_table = NODE_V6RT_TABLE(node);
    nxthop_proto_id_t proto = l3_rt_map_proto_id_to_nxthop_index(proto_id);

    ipv6_route_t *route = l3rib_v6route_lookup_exact_match (
                                NODE_V6RT_TABLE(node), prefix, prefix_len);

    if (!route) {
        cprintf ("Route not found\n");
        return false;
    }

    v6nexthop_t *nexthop = v6nexthop_find (route->nexthops[proto], 
                                                    gw, oif ? oif->ifindex : 0, proto_id, &index);

    if (!nexthop)
    {
        cprintf("Route's nexthop is not found\n");
        return false;
    }

    route->nexthops[proto][index] = NULL;
    delete (nexthop);
    route->nh_count--;

    if (route->nh_count)
    {
        // cprintf ("Route deleted successfully\n");
        return true;
    }

    bitmap_t prefix_bm, mask_bm;
    mtrie_node_t *mnode;

    bitmap_init(&prefix_bm, 128);
    bitmap_init(&mask_bm, 128);

    memcpy(prefix_bm.bits, prefix->addr, 16);
    for (int i = 0; i < prefix_len; i++)
        bitmap_set_bit_at(&mask_bm, i);
    bitmap_inverse (&mask_bm, 128);

    assert (mtrie_delete_prefix(&rt_table->route_list, 
                                            &prefix_bm,
                                            &mask_bm,
                                            (void **)&route) == MTRIE_DELETE_SUCCESS);

    //cprintf ("Route deleted successfully\n");
    bitmap_free_internal(&prefix_bm);
    bitmap_free_internal(&mask_bm);
    l3_v6route_dec_ref_count(route);
    return true;
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

    cprintf("L3 v6 Routing Table:\n");

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

                switch (nxthop_proto)
                {
                    case proto_nxthop_static:
                    case proto_nxthop_isis:
                    break;
                    case proto_nxthop_srv6:
                        cprintf (" SRv6 End Function : %s (%s)\n", 
                            end_fn_str(nexthop->u.srv6.endfn), 
                            flavor_str(nexthop->u.srv6.srv6_flavors));
                    break;
                }

                if (is_ipv6_addr_unspecified (&nexthop->gw.addr)) {
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

bool 
ipv6_add_route_to_rib (rt_table_t *v6_rt_table,
                                      ipv6_route_t *route) {

    mtrie_node_t *mnode;
    bitmap_t prefix_bm, mask_bm;
    mtrie_ops_result_code_t rc;

    bitmap_init(&prefix_bm, 128);
    bitmap_init(&mask_bm, 128);

    memcpy(prefix_bm.bits, &route->prefix.addr, 16);
    for (int i = 0; i < route->prefix_len; i++)
        bitmap_set_bit_at(&mask_bm, i);
    bitmap_inverse (&mask_bm, 128);

    rc = mtrie_insert_prefix(&v6_rt_table->route_list,
                             &prefix_bm,
                             &mask_bm,
                             128,
                             &mnode);

    bitmap_free_internal(&prefix_bm);
    bitmap_free_internal(&mask_bm);

    if (rc != MTRIE_INSERT_SUCCESS){
        cprintf ("Error : Route insertion failed, ret code = %d\n", rc);
        return false;
    }

    mnode->data = (void *)route;
    l3_v6route_inc_ref_count(route);
    route->install_time = time(NULL);
    return true;
}