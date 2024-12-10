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


void 
 layer3_ipv6_forward_nexthop (node_t *node, ipv6_route_t *route, pkt_block_t *pkt_block) {


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
        route->spf_metric[proto_id] = spf_metric;
        route->nh_count = 0;
        route->install_time = time(NULL);
        route->rt_ref_count = 0;
        route->endfn = endfn;
        route->flavor = srv6_flavor;
        route->nxthop_idx = 0;
        route->rt_flags = rt_flags;
        init_glthread(&route->notif_glue);
        init_glthread(&route->flash_glue);
        new_route = true;
    }

    if (!new_route)  {
        
        nexthop = v6nexthop_find (route->nexthops[proto_id], 
            gw, oif ? oif->ifindex : 0, proto, NULL);
        
        if (nexthop) {
            cprintf ("Route with this Nexthop already exists\n");
            return false;
        }

        if (route->nh_count >= MAX_NXT_HOPS) {
            cprintf ("Max nexthops reached for this route\n");
            return false;
        }
    }

    if (!nexthop) {

        nexthop = new v6nexthop_t;
        nexthop->ifindex = oif ? oif->ifindex : 0;
        if (gw) memcpy (nexthop->gw.addr, gw->addr, 16);
        nexthop->proto = proto;
        nexthop->oif = oif ? oif->GetSharedPtr() : nullptr;
        nexthop->ref_count = 0;
        nexthop->hit_count = 0;
        v6nh_insert_new_nexthop_nh_array (route->nexthops[proto_id], nexthop);
        route->nh_count++;
        route->is_direct = false;
    }

    if (!new_route)
        return true;

    mtrie_node_t *mnode;
    bitmap_t prefix_bm, mask_bm;
    mtrie_ops_result_code_t rc;

    bitmap_init(&prefix_bm, 128);
    bitmap_init(&mask_bm, 128);

    memcpy(prefix_bm.bits, prefix->addr, 16);
    for (int i = 0; i < prefix_len; i++)
        bitmap_set_bit_at(&mask_bm, i);
    bitmap_inverse (&mask_bm, 128);

   // cprintf ("Prefix to be inserted\n");
   // bitmap_prefix_print (&prefix_bm, &mask_bm, 128);

    rc = mtrie_insert_prefix(&rt_table->route_list,
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

                cprintf (" Proto : %s\n",  proto_name_str(route->nexthops[nxthop_proto][i]->proto));
                switch (nxthop_proto)
                {
                    case proto_nxthop_static:
                    case proto_nxthop_isis:
                    break;
                    case proto_nxthop_srv6:
                        cprintf (" SRv6 End Function : %s (%s)\n", 
                            end_fn_str(route->endfn), flavor_str(route->flavor));
                    break;
                }

                //cprintf (" Gateway : %s\n", inet_ntop6(&route->nexthops[nxthop_proto][i]->gw, buffer1));

                oif_name = route->nexthops[nxthop_proto][i]->oif ? \
                    (char *)route->nexthops[nxthop_proto][i]->oif->if_name.c_str() : NULL;

                cprintf(" OIF : %s\n", oif_name ? oif_name : "null");
                cprintf (" Hit Count : %llu\n", route->nexthops[nxthop_proto][i]->hit_count);
            }
        }
        cprintf ("\n");
    } ITERATE_GLTHREAD_END(&rt_table->route_list.list_head, curr);
    
} 