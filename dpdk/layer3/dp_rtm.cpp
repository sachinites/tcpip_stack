#include <stdbool.h>
#include <assert.h>
#include <arpa/inet.h>
#include "dp_rtm.h"
#include "../../Layer3/layer3.h"
#include "../../graph.h"
#include "../../common/cp2dp.h"
#include "../../net.h"
#include "../../utils.h"
#include "../../Layer3/rt_table/nexthop.h"
#include "../../Layer3/ipv6/ipv6_route.h"
#include "../../Layer3/ipv6/ipv6_hdrs.h"
#include "../../Layer3/ipv6/ipv6_utils.h"
#include "../../Interface/InterfaceUApi.h"
#include "../../Tracer/tracer.h"
#include "../../mtrie/mtrie.h"
#include "../../Layer3/rt_table/nexthop.h"
#include "../../Layer3/rt_notif.h"
#include "../../prefix-list/prefixlst.h"

/* IPV4 RTM */

/*
 * Insert nexthop using insertion sort on ifindex
 * */
static bool
l3_route_insert_nexthop(l3_route_t *l3_route,
						 nexthop_t *nexthop,
                         nxthop_proto_id_t nxthop_proto) {

	int i;

	nexthop_t *temp;
	nexthop_t **nexthop_arr;

	nexthop_arr = l3_route->nexthops[nxthop_proto];

	if (nexthop_arr[MAX_NXT_HOPS - 1]) {

		return false;
	}

	nexthop_arr[MAX_NXT_HOPS - 1] = nexthop;
	nexthop->ref_count++;

	i = MAX_NXT_HOPS - 1;

	while(i > 0 &&
		 (!nexthop_arr[i-1] ||
		    (nexthop_arr[i-1]->ifindex >
		     nexthop_arr[i]->ifindex))) {

		temp = nexthop_arr[i-1];
		nexthop_arr[i-1] = nexthop_arr[i];
		nexthop_arr[i] = temp;
		i--;
	}
	l3_route->install_time = time(NULL);
    l3_route->nh_count++;
	return true;
}

static bool
rt_table_evaluate_import_policy(rt_table_t *rt_table, l3_route_t *l3_route) {

    uint32_t prefix;

    if (!rt_table->import_policy) return true;

    prefix = tcp_ip_convert_ip_p_to_n(l3_route->dest);

    pfx_lst_result_t policy_res = prefix_list_evaluate (
                                                    prefix,
                                                    l3_route->mask,
                                                    rt_table->import_policy) ;

    switch (policy_res) {
        case PFX_LST_DENY:
            return false;
        case PFX_LST_PERMIT:
            return true;
        case PFX_LST_SKIP:
            return true;
        case PFX_LST_UNKNOWN:
            assert(0);
    }
    return false;
}


static bool
_rt_table_entry_add(rt_table_t *rt_table, l3_route_t *l3_route){

    mtrie_node_t *mnode;
    uint32_t bin_ip, bin_mask;
    bitmap_t prefix_bm, mask_bm;
    mtrie_ops_result_code_t rc;

    if (!rt_table_evaluate_import_policy(rt_table, l3_route)) {
        tracer(rt_table->node->dptr, DRTM , "Route %s/%d : Installation Rejected due to Import policy\n",  l3_route->dest, l3_route->mask );
        return false;
    }

   bin_ip = tcp_ip_convert_ip_p_to_n(l3_route->dest);
   bin_ip = htonl(bin_ip);
   bin_mask = tcp_ip_convert_dmask_to_bin_mask(l3_route->mask);
   bin_mask = ~bin_mask;
   bin_mask = htonl(bin_mask);

   bitmap_init(&prefix_bm, 32);
   bitmap_init(&mask_bm, 32);

   prefix_bm.bits[0] = bin_ip;
   mask_bm.bits[0] = bin_mask;

   rc = mtrie_insert_prefix(&rt_table->route_list,
                            &prefix_bm,
                            &mask_bm,
                            32,
                            &mnode);

   bitmap_free_internal(&prefix_bm);
   bitmap_free_internal(&mask_bm);

   if (rc != MTRIE_INSERT_SUCCESS)
       return false;

   mnode->data = (void *)l3_route;
   l3_route_inc_ref_count (l3_route);
   l3_route->install_time = time(NULL);
    tracer(rt_table->node->dptr, DRTM , "Route %s/%d : Successfully added to Rib\n",
            l3_route->dest, l3_route->mask);
   rt_table_add_route_to_notify_list(rt_table, l3_route, RT_ADD_F);
   rt_table_kick_start_notif_job(rt_table);
   return true;
}


static void
dp_ipv4_rt_table_add_route (rt_table_t *rt_table,
                                const char *dst,
                                char mask,
                                const char *gw,
                                Interface *oif,
                                uint32_t spf_metric,
                                uint16_t proto_id) {

   bool new_route = false;
    node_t *node = rt_table->node;

    nxthop_proto_id_t nxthop_proto =
        l3_rt_map_proto_id_to_nxthop_index(proto_id);

  assert (nxthop_proto < proto_nxthop_max);

   l3_route_t *l3_route = rt_table_lookup_exact_match(
                                            rt_table, (c_string)dst, mask);

   if(!l3_route){
       l3_route = l3_route_get_new_route();
       string_copy((char *)l3_route->dest, dst, 16);
       l3_route->dest[15] = '\0';
       l3_route->mask = mask;
       new_route = true;
       l3_route->is_direct = true;
       l3_route->nh_count = 0;
   }

   int i = 0;

   /*Get the index into nexthop array to fill the new nexthop*/
   if(!new_route){

       for( ; i < MAX_NXT_HOPS; i++){

           if (l3_route->nexthops[nxthop_proto][i]){

                if (gw && string_compare(l3_route->nexthops[nxthop_proto][i]->gw_ip, gw, 16) == 0 &&
                    l3_route->nexthops[nxthop_proto][i]->oif.get() == oif) {

                    tracer(node->dptr, DRTM | DERR,
                        "Error : Route %s/%d : Attempt to Add Duplicate \n", dst, mask);
                    return;
                }
           }
           else break;
       }
   }

   if( i == MAX_NXT_HOPS){
        tracer(node->dptr, DRTM | DERR,  "Error : Route %s/%d : No Space left for Nexthop \n", dst, mask);
        return;
   }

   if(oif){

        nexthop_t *nexthop = new nexthop_t;
        if (gw) l3_route->is_direct = false;
        l3_route->spf_metric[nxthop_proto] = spf_metric;
        if (gw) {
            string_copy((char *)nexthop->gw_ip, gw, 16);
        }
        else {
            nexthop->gw_ip[0] = '\0';
        }
        nexthop->gw_ip[15] = '\0';
        nexthop->proto = proto_id;
        nexthop->oif = oif->GetSharedPtr();
        nexthop->ifindex = oif->ifindex;

	l3_route_insert_nexthop(l3_route, nexthop, nxthop_proto);

	if (!new_route) {
            tracer(node->dptr, DRTM, "Route %s/%d : Nexthop %s %s added to Rib\n",
                dst, mask, nexthop->gw_ip, nexthop->oif ? nexthop->oif->if_name.c_str() : "None");
            rt_table_add_route_to_notify_list (rt_table, l3_route, RT_UPDATE_F);
            rt_table_kick_start_notif_job(rt_table);
        }
   }

   if (new_route){
       if (!_rt_table_entry_add(rt_table, l3_route)){
           tracer(node->dptr, DRTM | DERR, "Error : Route %s/%d : Installation Failed in Rib\n",  dst, mask);
       }
   }
}

static void
dp_ipv4_rt_table_delete_route (
        rt_table_t *rt_table,
        c_string ip_addr,
        char mask,
        uint16_t proto_id) {

    int count;
    l3_route_t *l3_route = NULL;
    uint32_t bin_ip, bin_mask;
    bitmap_t prefix_bm, mask_bm;

    l3_route = rt_table_lookup_exact_match(rt_table, ip_addr, mask);

    if (!l3_route) {
        return;
    }

    bin_ip = tcp_ip_convert_ip_p_to_n(ip_addr);
    bin_ip = htonl(bin_ip);
    bin_mask = tcp_ip_convert_dmask_to_bin_mask((uint8_t)mask);
    bin_mask = ~bin_mask;
    bin_mask = htonl(bin_mask);

    nxthop_proto_id_t nh_proto = l3_rt_map_proto_id_to_nxthop_index(proto_id);
    count = nh_flush_nexthops(l3_route->nexthops[nh_proto]);
    l3_route->spf_metric[nh_proto] = 0;
    l3_route->nh_count -= count;

    if (l3_route->nh_count) {
        tracer(rt_table->node->dptr, DRTM,
            "Route %s/%d : Nexthop of type %s deleted successfully from Rib\n",
            l3_route->dest, l3_route->mask, proto_index_to_str(nh_proto));
        return;
    }

    bitmap_init(&prefix_bm, 32);
    bitmap_init(&mask_bm, 32);

    prefix_bm.bits[0] = bin_ip;
    mask_bm.bits[0] = bin_mask;

    assert (mtrie_delete_prefix(&rt_table->route_list,
                                            &prefix_bm,
                                            &mask_bm,
                                            (void **)&l3_route) == MTRIE_DELETE_SUCCESS);

    tracer(rt_table->node->dptr, DRTM,
        "Route %s/%d : deleted successfully from Rib\n",  l3_route->dest, l3_route->mask);

    bitmap_free_internal(&prefix_bm);
    bitmap_free_internal(&mask_bm);
    rt_table_add_route_to_notify_list (rt_table, l3_route, RT_DEL_F);
    l3_route_dec_ref_count(l3_route);
    rt_table_kick_start_notif_job(rt_table);
}

void 
np_rt_table_process_msg(node_t *node, dp_msg_t *dp_msg) {

    unsigned char gw_str[16];
    unsigned char dest_str[16];
    rt_update_msg_t *rt_update_msg;

    rt_table_t *rt_table = NODE_RT_TABLE(node);

    assert (dp_msg->component_type == RT_TABLE_IPV4);

    switch (dp_msg->opr_type) {

        case DP_CREATE:

            rt_update_msg = (rt_update_msg_t *)dp_msg->data;

            dp_ipv4_rt_table_add_route (rt_table,
                    (const char *)tcp_ip_covert_ip_n_to_p (rt_update_msg->prefix, dest_str),
                    rt_update_msg->mask,
                    rt_update_msg->gateway ? 
                    (const char *)tcp_ip_covert_ip_n_to_p (rt_update_msg->gateway, gw_str) : NULL,
                    node_get_intf_by_ifindex (node, rt_update_msg->ifindex),
                    rt_update_msg->metric,
                    rt_update_msg->proto_id);
            break;

        case DP_DEL:

             rt_update_msg = (rt_update_msg_t *)dp_msg->data;
             dp_ipv4_rt_table_delete_route (rt_table,
                        (unsigned char *)tcp_ip_covert_ip_n_to_p (rt_update_msg->prefix, dest_str),
                        rt_update_msg->mask,
                        rt_update_msg->proto_id);
            break;

        case DP_UPDATE:
            //rt_table_update_route(rt_table, (rt_table_entry_t *)dp_msg->data);
            break;
            
        case DP_READ:
            break;
        default:
            break;
    }
    cp2dp_msg_free (dp_msg);
}

 /* ---------------------------------------------------------------------------   */

/* IPV6 RTM */
static bool
ipv6_add_route_to_rib (rt_table_t *v6_rt_table,
                                      ipv6_route_t *route) {

    char ipv6_addr_str[48];
    node_t *node = v6_rt_table->node;
    mtrie_node_t *mnode;
    bitmap_t prefix_bm, mask_bm;
    mtrie_ops_result_code_t rc;

    bitmap_init(&prefix_bm, 128);
    bitmap_init(&mask_bm, 128);

    ipv6_copy_bitmap (&route->prefix.addr, &prefix_bm);

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

        tracer (node->dptr, DRTM | DERR, 
            "%s : Error : Route %s/%d insertion failed, ret code = %d\n", node->node_name, 
            inet_ntop6 (&route->prefix, ipv6_addr_str), route->prefix_len, rc);
        cprintf ("%s : Error : Route %s/%d insertion failed, ret code = %d\n", node->node_name, 
            inet_ntop6 (&route->prefix, ipv6_addr_str), route->prefix_len, rc);

        return false;
    }

    mnode->data = (void *)route;
    l3_v6route_inc_ref_count(route);
    route->install_time = time(NULL);

    tracer (node->dptr, DRTM, 
        "%s : Route %s/%d installed successfully\n", node->node_name, 
        inet_ntop6 (&route->prefix, ipv6_addr_str), route->prefix_len);
    #if 0
    cprintf ("%s : Route %s/%d installed successfully\n", node->node_name, 
        inet_ntop6 (&route->prefix, ipv6_addr_str), route->prefix_len);
    #endif 

    return true;
}

bool
 dp_ipv6_route_install (node_t *node,
                                ipv6_addr_t *prefix,
                                uint8_t prefix_len,
                                uint8_t rt_flags,
                                ipv6_addr_t *gw,
                                Interface* oif,   // can be NULL
                                uint8_t seg_lst_count,
                                uint8_t (*seg_lst)[16],
                                uint32_t spf_metric,
                                Srv6_endpcode_t endfn,
                                uint16_t proto ) {


    bool new_route = false;
    v6nexthop_t *nexthop = NULL;

    rt_table_t *rt_table = NODE_V6RT_TABLE(node);

    nxthop_proto_id_t proto_id = l3_rt_map_proto_id_to_nxthop_index (proto);

    if (proto_id == proto_nxthop_max) {
        tracer (node->dptr, DRTM | DERR, "%s : Error : Invalid proto_id\n", node->node_name);
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
        tracer (node->dptr, DRTM | DERR, 
            "%s : Error : Max nexthops reached for this route\n", node->node_name);
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
        nexthop->metric = spf_metric;
        nexthop->hit_count = 0;
        nexthop->flags = rt_flags;
        route->is_direct = false;

        if (proto == PROTO_SRv6)
        {
            nexthop->u.srv6.endfn = endfn;

            if (seg_lst_count) {

                nexthop->u.srv6.n_segment_list = seg_lst_count;
                nexthop->u.srv6.segment_lst = (ipv6_addr_t *)calloc (seg_lst_count, sizeof (ipv6_addr_t));

                for (int i = 0; i < seg_lst_count; i++) {
                    memcpy (nexthop->u.srv6.segment_lst[i].addr , (*(seg_lst + i)), 16);
                }
            }
        }
    }

    /* Handle direct routes */
    if (new_route && !nexthop) {
        return ipv6_add_route_to_rib  (rt_table, route);
    }

    if (new_route) {
        v6nh_insert_new_nexthop_nh_array(
            route->nexthops[proto_id], nexthop);
        route->nh_count++;
        return ipv6_add_route_to_rib  (rt_table, route);
    }

    /* Installing a duplicate route without nexthop again !*/
    if (!nexthop) return false;

    int index;
    int res = v6nh_is_nexthop_exist_in_nh_array (
            route->nexthops[proto_id], nexthop, &index) ;

    switch (res)
    {
    case 0:
        tracer (node->dptr, DRTM | DERR, "%s : Error : Nexthop already exists\n", 
            node->node_name);
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
 dp_ipv6_route_uninstall (node_t *node,
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
        tracer (node->dptr, DRTM | DERR, "%s : Error : Route not found\n", 
            node->node_name);
        return false;
    }

    v6nexthop_t *nexthop = v6nexthop_find (route->nexthops[proto],
                                                    gw, oif ? oif->ifindex : 0, proto_id, &index);

    if (!nexthop)
    {
        tracer (node->dptr, DRTM | DERR, "%s : Route's nexthop is not found\n", 
            node->node_name);
        return false;
    }

    route->nexthops[proto][index] = NULL;
    delete (nexthop);
    route->nh_count--;

    if (route->nh_count)
    {
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

    bitmap_free_internal(&prefix_bm);
    bitmap_free_internal(&mask_bm);
    l3_v6route_dec_ref_count(route);
    return true;
}

void
np_rt6_table_process_msg(node_t *node, dp_msg_t *dp_msg) {

    ipv6_addr_t gw;
    ipv6_addr_t dest;

    rt6_update_msg_t *rt_update_msg;

    rt_table_t *ipv6_rt_table = NODE_V6RT_TABLE(node);

    assert (dp_msg->component_type == RT_TABLE_IPV6);

    switch (dp_msg->opr_type) {

        case DP_CREATE:
            rt_update_msg = (rt6_update_msg_t *)dp_msg->data;      
            memcpy (dest.addr , rt_update_msg->prefix, 16);
            memcpy (gw.addr , rt_update_msg->gateway, 16);
            dp_ipv6_route_install (node,
                                                 &dest,
                                                 rt_update_msg->prefix_len,
                                                 rt_update_msg->rt_flags,
                                                 &gw,
                                                 node_get_intf_by_ifindex (node, rt_update_msg->ifindex),
                                                 rt_update_msg->seg_lst_count,
                                                 (uint8_t (*)[16]) (rt_update_msg->seg_lst_count ? \
                                                 rt_update_msg->seglst : NULL),
                                                 rt_update_msg->metric,
                                                 (Srv6_endpcode_t )rt_update_msg->srv6_end_fn,
                                                rt_update_msg->proto_id);

            break;

        case DP_DEL:

             rt_update_msg = (rt6_update_msg_t *)dp_msg->data;
            memcpy (dest.addr , rt_update_msg->prefix, 16);
            memcpy (gw.addr , rt_update_msg->gateway, 16);
             dp_ipv6_route_uninstall (node,
                                                 &dest,
                                                 rt_update_msg->prefix_len,
                                                 &gw,
                                                 node_get_intf_by_ifindex (node, rt_update_msg->ifindex),
                                                 rt_update_msg->proto_id);
            break;

        case DP_UPDATE:
            //rt_table_update_route(rt_table, (rt_table_entry_t *)dp_msg->data);
            break;

        case DP_READ:
            break;
        default:
            break;
    }
    cp2dp_msg_free (dp_msg);
}