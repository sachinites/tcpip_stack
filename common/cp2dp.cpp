#include <assert.h>
#include "cmn_prefix.h"
#include "../router_init.h"
#include "l3_hdrs.h"
#include "cp2dp.h"
#include "../EventDispatcher/event_dispatcher.h"
#include "../dpdk/layer3/dp_rtm.h"
#include "../Layer2/mac_table.h"
#include "../Layer3/layer3.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../pkt_block.h"
#include "../Interface/InterfaceUApi.h"
#include "../Tracer/tracer.h"
#include "../Layer3/ipv6/ipv6_hdrs.h"
#include "../Layer3/mpls_fwd.h"
#include "../Layer3/rt_table/nexthop.h"
#include "../lmm_enums.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../RTM/rtm_nb_integ.h"
#include "../RTM/rtm_nh.h"
#include "../FIB/fib.h"
#include "../FIB/fib_route.h"
#include "../FIB/fib_nh.h"

extern void
np_tcp_ip_send_ip6_data (node_t *node, pkt_block_t *pkt_block);

extern bool 
_rt_table_entry_add(rt_table_t *rt_table, l3_route_t *l3_route);

static void 
dp_mac_table_process_msg(node_t *node, dp_msg_t *dp_msg) {
    
    mac_update_msg_t *mac_update_msg;
    mac_table_t *mac_table = NODE_MAC_TABLE(node);
    
    assert(dp_msg->component_type == MAC_TABLE);
    
    switch (dp_msg->opr_type) {
        
        case DP_CREATE:
            mac_update_msg = (mac_update_msg_t *)dp_msg->data;
            mac_table_entry_add (node, NODE_MAC_TABLE(node), 
                                                    mac_update_msg->mac_addr,   
                                                    mac_update_msg->vlan_id,
                                                    mac_update_msg->ifindex,
                                                    mac_update_msg->flags,
                                                    mac_update_msg->remote_dst_ip);
            break;
            
        case DP_DEL:
            mac_update_msg = (mac_update_msg_t *)dp_msg->data;
            mac_table_entry_delete (node, NODE_MAC_TABLE(node), 
                                                    mac_update_msg->mac_addr,   
                                                    mac_update_msg->vlan_id,
                                                    mac_update_msg->ifindex,
                                                    mac_update_msg->remote_dst_ip);
            break;
            
        case DP_UPDATE:
            // Handle MAC entry updates if needed
            break;
            
        case DP_READ:
            // Handle MAC table reads if needed
            break;
            
        default:
            break;
    }
    
    cp2dp_msg_free(dp_msg);
}


static void
np_recv_cp_pkt_block(node_t *node, dp_msg_t *dp_msg)
{
    pkt_block_t *pkt_block;
    hdr_type_t hdr_type;

    pkt_block = *(pkt_block_t **)dp_msg->data;

    switch (dp_msg->opr_type)
    {
        case DP_L3_NORTHBOUND_IN:
        {
            hdr_type = pkt_block_get_starting_hdr(pkt_block);

            switch (hdr_type)
            {
            case IP_HDR:
                np_tcp_ip_send_ip_data(node, pkt_block);
                break;
            case IP6_HDR:
                np_tcp_ip_send_ip6_data(node, pkt_block);
                break;
            default:
                break;
            }
        }
    break;

    default:
        break;
    }

    pkt_block_dereference(pkt_block);
    cp2dp_msg_free(dp_msg);
}

static void
dp_ipv4_mpls_table_process_msg(node_t *node, dp_msg_t *dp_msg);

static void
dp_mpls_table_process_msg(node_t *node, dp_msg_t *dp_msg) {
    
    mpls_route_update_msg_t *mpls_update_msg;
    nexthop_t *nexthop;
    mpls_lstack_t *lstack;
    Interface *oif;
    char ip_addr_str[IPV4_ADDR_LEN_STR];
    struct hashtable *ht;

    assert(dp_msg->component_type == MPLS_TABLE);
    
    switch (dp_msg->opr_type) {
        
        case DP_CREATE:
            mpls_update_msg = (mpls_route_update_msg_t *)dp_msg->data;
            
            /* Get the interface */
            oif = node_get_intf_by_ifindex(node, mpls_update_msg->ifindex);
            if (!oif) {
                tracer (node->dptr, DMPLS | DERR, 
                       "MPLS RIB : Interface with index %d not found\n", 
                       mpls_update_msg->ifindex);
                cp2dp_msg_free(dp_msg);
                return;
            }
            
            /* Create nexthop */
            nexthop = nh_create_new_nexthop(
                (c_string)node->node_name,
                mpls_update_msg->ifindex,
                tcp_ip_covert_ip_n_to_p (mpls_update_msg->gw_ip, (c_string)ip_addr_str),
                PROTO_STATIC);
            
            if (!nexthop) {
                tracer (node->dptr, DMPLS | DERR, 
                       "MPLS RIB : Failed to create nexthop\n");
                cp2dp_msg_free(dp_msg);
                return;
            }
            
            nexthop->oif = oif->GetSharedPtr();
            
            /* Create and populate label stack if labels are provided */
            if (mpls_update_msg->label_stack_count > 0) {
                lstack = (mpls_lstack_t *)XCALLOC2(0, 1, mpls_lstack_t);
                lstack->curr_index = 0;
                
                for (int i = 0; i < mpls_update_msg->label_stack_count && i < MAX_LBL_DEPTH; i++) {
                    /* Copy the encoded label value directly */
                    lstack->labels[i].label_val = mpls_update_msg->label_stack[i].label_val;
                    lstack->labels[i].op = mpls_update_msg->label_stack[i].op;
                }
                
                nexthop->lbls = lstack;
            }
            
            /* Install the MPLS route */
             if (!mpls_install_route(node, mpls_update_msg->in_label, nexthop)){
                 nexthop_dereference(nexthop);
                 tracer (node->dptr, DMPLS | DERR, 
                    "MPLS RIB : Route installation Failed - in_label=%d, gw=%s, oif=%s\n",
                    mpls_label_get_value(mpls_update_msg->in_label), 
                    ip_addr_str,
                    oif->if_name.c_str());
                 cp2dp_msg_free(dp_msg);
                 return;
             }
            
            tracer (node->dptr, DMPLS, 
                   "MPLS RIB : Route installed Successfully - in_label=%d, gw=%s, oif=%s\n",
                   mpls_label_get_value(mpls_update_msg->in_label), 
                   ip_addr_str,
                   oif->if_name.c_str());
            
            break;
            
        case DP_DEL:
        {
            mpls_update_msg = (mpls_route_update_msg_t *)dp_msg->data;
            
            /* Decode the label value for deletion */
            mpls_label_val_t label_val = mpls_label_get_value(mpls_update_msg->in_label);
            
            /* Get the MPLS routing table */
            ht = NODE_MPLS_RT_TABLE(node)->ht;
            
            /* Search for the route */
            mpls_route_t *mpls_route = (mpls_route_t *)hashtable_search(ht, (void *)&label_val);
            
            if (!mpls_route) {
                tracer (node->dptr, DMPLS | DERR, 
                       "MPLS RIB : Route %d not found, deletion failed\n", label_val);
                cp2dp_msg_free(dp_msg);
                return;
            }
            
            /* Check if specific nexthop deletion or full route deletion */
            if (mpls_update_msg->gw_ip != 0 && mpls_update_msg->ifindex != 0) {
                /* Specific nexthop deletion */
                
                /* Get interface */
                oif = node_get_intf_by_ifindex(node, mpls_update_msg->ifindex);
                if (!oif) {
                    tracer (node->dptr, DMPLS | DERR, 
                           "MPLS RIB : Interface with index %d not found for nexthop deletion\n", 
                           mpls_update_msg->ifindex);
                    cp2dp_msg_free(dp_msg);
                    return;
                }
                
                /* Create temporary nexthop for comparison */
                nexthop = nh_create_new_nexthop(
                    (c_string)node->node_name,
                    mpls_update_msg->ifindex,
                    tcp_ip_covert_ip_n_to_p(mpls_update_msg->gw_ip, (c_string)ip_addr_str),
                    PROTO_STATIC);
                
                nexthop->oif = oif->GetSharedPtr();
                
                /* Create label stack if provided */
                if (mpls_update_msg->label_stack_count > 0) {
                    lstack = (mpls_lstack_t *)XCALLOC2(0, 1, mpls_lstack_t);
                    lstack->curr_index = 0;
                    
                    for (int i = 0; i < mpls_update_msg->label_stack_count && i < MAX_LBL_DEPTH; i++) {
                        lstack->labels[i].label_val = mpls_update_msg->label_stack[i].label_val;
                        lstack->labels[i].op = mpls_update_msg->label_stack[i].op;
                    }
                    
                    nexthop->lbls = lstack;
                }
                
                /* Use existing mpls_uninstall_route to remove specific nexthop */
                mpls_uninstall_route(node, mpls_update_msg->in_label, nexthop);
                
                /* Clean up temporary nexthop */
                nexthop_dereference(nexthop);
                
                tracer (node->dptr, DMPLS, 
                       "MPLS RIB : Nexthop removed from route %d\n", label_val);
                
            } else {
                /* Full route deletion - remove all nexthops */
                
                labelled_nxthop_proto_id_t nh_proto;
                FOR_ALL_LABELLED_NXTHOP_PROTO(nh_proto) {
                    for (int i = 0; i < MAX_NXT_HOPS; i++) {
                        if (mpls_route->nexthops[nh_proto][i]) {
                            nexthop_dereference(mpls_route->nexthops[nh_proto][i]);
                            mpls_route->nexthops[nh_proto][i] = NULL;
                        }
                    }
                }
                
                /* Remove from hashtable (hashtable will free the key) */
                mpls_route = (mpls_route_t *)hashtable_remove(ht, (void *)&label_val);
                
                if (mpls_route) {
                    tracer (node->dptr, DMPLS, 
                           "MPLS RIB : Route %d deleted successfully\n", label_val);
                    XFREE(mpls_route);
                } else {
                    tracer (node->dptr, DMPLS | DERR, 
                           "MPLS RIB : Route %d hashtable removal failed\n", label_val);
                }
            }
            
            break;
        }
            
        case DP_UPDATE:
            /* TODO: Implement MPLS route update if needed */
            break;
            
        case DP_READ:
            /* TODO: Implement MPLS table reads if needed */
            break;
            
        default:
            break;
    }
    
    cp2dp_msg_free(dp_msg);
}


static void
dp_fib_table_process_msg(node_t *node, dp_msg_t *dp_msg) {
    
    char nh_str[48];
    char route_str[48];
    fib_error_t rc;
    fib_t *fib = NULL;
    fib_nh_t *nh = NULL;
    fib_update_msg_t *fib_update_msg;

    assert(dp_msg->component_type == FIB_TABLE);

    fib_update_msg = (fib_update_msg_t *)dp_msg->data;

    tracer (node->dptr, DFIB, 
        "FIB : Recvd fib update message : Route:%s vrf:%s idx[%u %u] ops:%d\n", 
            cmn_prefix_to_string(&fib_update_msg->prefix, &route_str), 
            vrf_name(node, fib_update_msg->target_fib_vrf_id), 
            fib_update_msg->inhidx >> 32, 
            fib_update_msg->nhidx & 0x00000000FFFFFFFF, 
            dp_msg->opr_type);

    switch (dp_msg->opr_type) {
        
        case DP_CREATE:
        {
            /* Select FIB based on nexthop address AFI */
            fib = fib_get (node, 
                    (AFI_T)fib_update_msg->target_fib_afi,
                     fib_update_msg->target_fib_vrf_id);
        
            if (!fib) {
                tracer (node->dptr, DFIB | DERR, 
                       "FIB : FIB not initialized for AFI:%d VRF:%d\n",
                       fib_update_msg->target_fib_afi, 
                       fib_update_msg->target_fib_vrf_id);
                cp2dp_msg_free(dp_msg);
                return;
            }
            
            /* Create nexthop from forwarding info */
            fib_nh_t nh_template;
            memset (&nh_template, 0, sizeof(fib_nh_t));
            avltree_node_init (&nh_template.idx_glue);

            nh_template.fwd_info = new fib_nh_fwd_info_t;
            rtm_fib_copy_fwd_info (node, 
                &fib_update_msg->fwd_info, nh_template.fwd_info);
            
            nh = fib_nh_lookup(fib, &nh_template);

            if (!nh) {

                nh = fib_nh_create(fib, &nh_template);
           
                if (!nh) {
                    tracer (node->dptr, DFIB | DERR, 
                        "FIB[%s] : Error : Route %s : Failed to create nexthop %s\n", 
                        fib->name,
                        route_str,
                        cmn_prefix_to_string(&nh_template.fwd_info->nh_addr, &nh_str));
                    delete nh_template.fwd_info;
                    cp2dp_msg_free(dp_msg);
                    return;
                }
                tracer (node->dptr, DFIB_DET, 
                    "FIB[%s] : Route %s : New nexthop %s Created and Registered\n", 
                    fib->name,
                    route_str,
                    cmn_prefix_to_string(&nh_template.fwd_info->nh_addr, &nh_str));
                fib_register_nh(fib, nh);
            }
            else {
                tracer (node->dptr, DFIB_DET, 
                    "FIB[%s] : Route %s : Existing nexthop %s Reused\n", 
                    fib->name, route_str,
                    cmn_prefix_to_string(&nh_template.fwd_info->nh_addr, &nh_str));
            }

            delete nh_template.fwd_info;

            rc = fib_add_route(node,
                    fib, 
                    &fib_update_msg->prefix, 
                    fib_update_msg->inhidx,
                    fib_update_msg->nhidx, nh);
            
            if (rc != FIB_ERROR_SUCCESS) {
                tracer (node->dptr, DFIB | DERR, 
                       "FIB[%s] : Failed to add route %s, error: %s\n",
                       fib->name, route_str, fib_error_str(rc));
                delete nh->fwd_info;
                XFREE(nh);
            }
            break;
        }
            
        case DP_DEL:
        {   
            fib = fib_get (node, 
                    (AFI_T)fib_update_msg->target_fib_afi,
                     fib_update_msg->target_fib_vrf_id);

            if (!fib) {
                tracer (node->dptr, DFIB | DERR, 
                       "FIB : FIB not initialized for AFI:%d VRF:%d\n",
                       fib_update_msg->target_fib_afi, 
                       fib_update_msg->target_fib_vrf_id);
                cp2dp_msg_free(dp_msg);
                return;
            }
            
            rc = fib_del_route(node, fib, 
                    &fib_update_msg->prefix, 
                    fib_update_msg->inhidx,
                    fib_update_msg->nhidx);
            
            if (rc != FIB_ERROR_SUCCESS) {
                tracer (node->dptr, DFIB | DERR, 
                       "FIB[%s] : Failed to delete route, error: %s\n",
                       fib->name, fib_error_str(rc));
            }
            break;
        }
            
        case DP_UPDATE:
            // Handle FIB entry updates if needed
            break;
            
        case DP_READ:
            // Handle FIB reads if needed
            break;
            
        default:
            break;
    }
    
    cp2dp_msg_free(dp_msg);
}

static void 
cp2dp_task_handler  (event_dispatcher_t *ev_dis,  void *arg, uint32_t arg_size) {

    // This function is the task handler for the task submitted to the Data Path (DP)
    // The task handler is called when the task is executed by the DP's event dispatcher
    // The task handler is called with the task data as arg

    dp_msg_t *dp_msg = (dp_msg_t *)arg;
    node_t *node = (node_t *)ev_dis->app_data;

    switch (dp_msg->component_type) {

        case RT_TABLE_IPV4:
            np_rt_table_process_msg (node, dp_msg);
            break;
        case RT_TABLE_IPV6:
            np_rt6_table_process_msg (node, dp_msg);
            break;
        case MAC_TABLE:
            dp_mac_table_process_msg (node, dp_msg);
            break;
        case PKT_BLOCK:
            np_recv_cp_pkt_block (node, dp_msg);
            break;
        case MPLS_TABLE:
            dp_mpls_table_process_msg (node, dp_msg);
            break;
        case IPV4_MPLS_TABLE:
            dp_ipv4_mpls_table_process_msg (node, dp_msg);
            break;
        case FIB_TABLE:
            dp_fib_table_process_msg (node, dp_msg);
            break;
        default:
            break;
    }
    node->cp2dp_msg_count++;
}

dp_msg_t *
cp2dp_msg_alloc () {

    return new dp_msg_t;
}

void
cp2dp_msg_free (dp_msg_t *dp_msg) {
    
        delete (dp_msg);
}


void 
dp_pkt_xmit_intf_job_cbk (event_dispatcher_t *ev_dis, void *pkt, uint32_t pkt_size){

    node_t *node;
    pkt_block_t *pkt_block;
	node_t *receving_node;
	Interface *xmit_intf;

	ev_dis_pkt_data_t *ev_dis_pkt_data  = 
			(ev_dis_pkt_data_t *)task_get_next_pkt(ev_dis, &pkt_size);

	if(!ev_dis_pkt_data) {
		return;
	}

    node = (node_t *)ev_dis->app_data;

	for ( ; ev_dis_pkt_data; 
			ev_dis_pkt_data = (ev_dis_pkt_data_t *) task_get_next_pkt(ev_dis, &pkt_size)) {

		receving_node = ev_dis_pkt_data->recv_node;
		xmit_intf = ev_dis_pkt_data->recv_intf.get();
		pkt_block = (pkt_block_t *)ev_dis_pkt_data->pkt;		
        tracer (node->dptr,  DIPC | DFLOW, "Pkt : %s : Recvd by Data path\n", pkt_block_str(pkt_block));
        xmit_intf->SendPacketOut (pkt_block);
        pkt_block_dereference(pkt_block);
	    delete (ev_dis_pkt_data);
	}
}

/* Fix me : cp2dp_xmit_pkt is allocated by CP but freed by DP. This is not a desirable thing to do.
    For now its not a problem, but in future when CP and DP will have separate memory mgr, 
    this would create problem.*/
void
cp2dp_xmit_pkt (node_t *node, pkt_block_t *pkt_block, Interface *xmit_interface) {
    
        ev_dis_pkt_data_t *ev_dis_pkt_data = new ev_dis_pkt_data_t;
        ev_dis_pkt_data->recv_node = node;
        ev_dis_pkt_data->recv_intf = xmit_interface->GetSharedPtr();
        ev_dis_pkt_data->pkt = (byte *)pkt_block;
        pkt_block_reference(pkt_block);
        tracer (node->cptr,  DIPC | DFLOW, "Pkt : %s : Xmit to Data path\n", pkt_block_str(pkt_block));
        pkt_q_enqueue(EV_DP(node), &node->cp_to_dp_xmit_intf_pkt_q ,
                  (char *)ev_dis_pkt_data, sizeof(ev_dis_pkt_data_t));
}

/* This is Control plane API to push IP data to be sent out from L4+ layer down to L3.
    pkt_block must contain IP payload . If there is no ip payload, then send NULL*/
void 
cp2dp_send_ip_data ( node_t *node, 
                     pkt_block_t *pkt_block,
                     uint32_t dest_ip_addr,
                     uint16_t std_ip_protocol) {

    bool new_pkt_block = false;

    if (!pkt_block) {
        pkt_block = pkt_block_get_new_pkt_buffer(sizeof(ip_hdr_t));
        new_pkt_block = true;
    }
    else {
        pkt_block_expand_buffer_left (pkt_block, sizeof (ip_hdr_t));
    }

    pkt_block_set_starting_hdr_type (pkt_block, IP_HDR);

    ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr(pkt_block);
    pkt_size_t pkt_size = pkt_block->pkt_size;

    initialize_ip_hdr (ip_hdr);

    ip_hdr->protocol = (uint8_t)std_ip_protocol;
    ip_hdr->src_ip = htonl(tcp_ip_convert_ip_p_to_n(NODE_RTRID_ADDR(node)));
    ip_hdr->dst_ip = htonl(dest_ip_addr);
    ip_hdr->total_length = htons(pkt_size);
    dp_msg_t *dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = PKT_BLOCK;
    dp_msg->opr_type = DP_L3_NORTHBOUND_IN;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(pkt_block_t *);
    memcpy (dp_msg->data, &pkt_block, sizeof(pkt_block_t *));
    pkt_block_reference(pkt_block);
    cp2dp_submit (node, dp_msg, true);
    if (new_pkt_block)pkt_block_dereference(pkt_block);
}

/* Write the ipv6 equivalent function of cp2dp_send_ip_data( )*/
void 
cp2dp_send_ip6_data ( node_t *node, 
                                    pkt_block_t *pkt_block,
                                    ipv6_addr_t dest_ip_addr,
                                    uint16_t std_ip_protocol) 
{
    bool new_pkt_block = false;
    pkt_size_t ipv6_payload_size = 0;

    if (!pkt_block) {
        pkt_block = pkt_block_get_new_pkt_buffer(sizeof(ipv6_hdr_t));
        new_pkt_block = true;
    }
    else {
        ipv6_payload_size = pkt_block->pkt_size;
        pkt_block_expand_buffer_left (pkt_block, sizeof (ipv6_hdr_t));
    }

    pkt_block_set_starting_hdr_type (pkt_block, IP6_HDR);

    pkt_size_t pkt_size;
    ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt_block_get_pkt (pkt_block, &pkt_size);

    initialize_ipv6_hdr (ipv6_hdr);

    ipv6_hdr->next_header = (uint8_t)(std_ip_protocol);
    ipv6_hdr->payload_length =  htons(ipv6_payload_size);
    memcpy (ipv6_hdr->dst_addr, dest_ip_addr.addr, 16);

    dp_msg_t *dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = PKT_BLOCK;
    dp_msg->opr_type = DP_L3_NORTHBOUND_IN;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(pkt_block_t *);
    memcpy (dp_msg->data, &pkt_block, sizeof(pkt_block_t *));
    pkt_block_reference(pkt_block);
    cp2dp_submit (node, dp_msg, true);
    if (new_pkt_block) pkt_block_dereference (pkt_block);
}

void 
cp2dp_submit (node_t *node, dp_msg_t *dp_msg, bool async) {

    // This function is used to submit a task to the DP
    // The task is submitted to the DP's event dispatcher
    // The task is submitted with the highest priority
    // The task is submitted as a one-shot task
    // The task is submitted with the task data as arg
    // The task data size is arg_size

    // Get the event dispatcher of the DP
    if (async) {
            task_create_new_job(EV_DP(node), (void *)dp_msg,
                cp2dp_task_handler, 
                TASK_ONE_SHOT, 
                TASK_PRIORITY_CP_TO_DP);
    }
    else {
        task_create_new_job_synchronous(EV_DP(node), (void *)dp_msg,
                cp2dp_task_handler, 
                TASK_ONE_SHOT, 
                TASK_PRIORITY_CP_TO_DP);
    }
}

void
ipv6_route_install (node_t *node,
                                ipv6_addr_t *prefix,
                                uint8_t prefix_len,
                                uint8_t rt_flags,
                                ipv6_addr_t *gw,
                                Interface* oif,
                                ipv6_addr_t (*segment_lst)[16],
                                uint32_t spf_metric,
                                Srv6_endpcode_t endfn,
                                uint16_t proto_id) {

    dp_msg_t *dp_msg = cp2dp_msg_alloc ();
    rt6_update_msg_t *rt_update_msg = (rt6_update_msg_t *)dp_msg->data;

    dp_msg->component_type = RT_TABLE_IPV6;
    dp_msg->opr_type = DP_CREATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(rt6_update_msg_t);

    memcpy (rt_update_msg->prefix, prefix->addr, 16);
    rt_update_msg->prefix_len = prefix_len;
    rt_update_msg->rt_flags = rt_flags;

    if (gw) {
        memcpy (rt_update_msg->gateway, gw->addr, 16);
    }
    else {
        memset (rt_update_msg->gateway, 0, 16);
    }

    if (oif) {
        rt_update_msg->ifindex = oif->ifindex;
    }
    else {
        rt_update_msg->ifindex = 0;
    }

    rt_update_msg->metric = spf_metric;
    rt_update_msg->srv6_end_fn = endfn;
    rt_update_msg->proto_id = proto_id;

    if (segment_lst) {

        int i = 0;

        while (  !is_ipv6_addr_unspecified ( &((*segment_lst)[i]).addr ) ) {
            memcpy ( rt_update_msg->seglst[i], &((*segment_lst)[i]).addr , 16 );
            i++;
        } 

        rt_update_msg->seg_lst_count = i;
        dp_msg->data_size += (i*16);
    }

    cp2dp_submit (node, dp_msg, true);
}

void
ipv6_route_uninstall (node_t *node,
                                    ipv6_addr_t *prefix,
                                    uint8_t prefix_len,
                                    ipv6_addr_t *gw,
                                    Interface* oif,
                                    uint16_t proto_id) {


    dp_msg_t *dp_msg = cp2dp_msg_alloc ();

    rt6_update_msg_t *rt_update_msg = (rt6_update_msg_t *)dp_msg->data;

    dp_msg->component_type = RT_TABLE_IPV6;
    dp_msg->opr_type = DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(rt6_update_msg_t);

    memcpy (rt_update_msg->prefix, prefix->addr, 16);
    rt_update_msg->prefix_len = prefix_len;

    if (gw) {
        memcpy (rt_update_msg->gateway, gw->addr, 16);
    }
    else {
        memset (rt_update_msg->gateway, 0, 16);
    }

    if (oif) {
        rt_update_msg->ifindex = oif->ifindex;
    }
    else {
        rt_update_msg->ifindex = 0;
    }

    rt_update_msg->proto_id = proto_id;

    cp2dp_submit (node, dp_msg, true);
}

/* Wrapper fn to add route to Routing table Asynchronously*/
void
rt_ipv4_route_add (node_t *node,
                                uint32_t prefix,
                                uint8_t mask,
                                uint32_t gw_ip,
                                Interface *oif,
                                uint32_t metric,
                                uint16_t proto_id,
                                bool async) {

    dp_msg_t *dp_msg;
    rt_update_msg_t *rt_update_msg;
    rt_table_t *rt_table = NODE_RT_TABLE(node);

    dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = RT_TABLE_IPV4;
    dp_msg->opr_type = DP_CREATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(rt_update_msg_t);
    rt_update_msg = (rt_update_msg_t *)dp_msg->data;
    rt_update_msg->prefix = prefix;
    rt_update_msg->mask = mask;
    rt_update_msg->gateway = gw_ip;
    rt_update_msg->ifindex = oif ? oif->ifindex : 0;
    rt_update_msg->metric = metric;
    rt_update_msg->proto_id = proto_id;
    cp2dp_submit(node, dp_msg, async);
}

void
rt_ipv4_route_del (node_t *node,
                                uint32_t prefix,
                                uint8_t mask,
                                uint16_t proto_id,
                                bool async) {

    dp_msg_t *dp_msg;
    rt_update_msg_t *rt_update_msg;
    rt_table_t *rt_table = NODE_RT_TABLE(node);

    dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = RT_TABLE_IPV4;
    dp_msg->opr_type = DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(rt_update_msg_t);
    rt_update_msg = (rt_update_msg_t *)dp_msg->data;
    rt_update_msg->prefix = prefix;
    rt_update_msg->mask = mask;
    rt_update_msg->proto_id = proto_id;
    cp2dp_submit(node, dp_msg, async);
}

/* Wrapper fn to add MAC entry to MAC table Asynchronously*/
void
cp2dp_mac_table_entry_add (node_t *node,
                      uint8_t *mac_addr,
                      uint16_t vlan_id,
                      uint32_t ifindex,
                      uint16_t flags,
                      bool async,
                      uint32_t remote_dst_ip) {

    dp_msg_t *dp_msg;
    mac_update_msg_t *mac_update_msg;

    dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = MAC_TABLE;
    dp_msg->opr_type = DP_CREATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(mac_update_msg_t);
    mac_update_msg = (mac_update_msg_t *)dp_msg->data;
    
    memcpy(mac_update_msg->mac_addr, mac_addr, 6);
    mac_update_msg->vlan_id = vlan_id;
    mac_update_msg->ifindex = ifindex;
    mac_update_msg->flags = flags;
    mac_update_msg->remote_dst_ip = remote_dst_ip;
    
    cp2dp_submit(node, dp_msg, async);
}

void
cp2dp_mac_table_entry_del (node_t *node,
                      uint8_t *mac_addr,
                      uint16_t vlan_id,
                      uint32_t ifindex,
                      bool async,
                      uint32_t remote_dst_ip) {

    dp_msg_t *dp_msg;
    mac_update_msg_t *mac_update_msg;

    dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = MAC_TABLE;
    dp_msg->opr_type = DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(mac_update_msg_t);
    mac_update_msg = (mac_update_msg_t *)dp_msg->data;
    
    memcpy(mac_update_msg->mac_addr, mac_addr, 6);
    mac_update_msg->vlan_id = vlan_id;
    mac_update_msg->ifindex = ifindex;
    mac_update_msg->remote_dst_ip = remote_dst_ip;
    mac_update_msg->flags = 0; // Not needed for delete
    
    cp2dp_submit(node, dp_msg, async);
}

/* Wrapper fn to install MPLS route Asynchronously */
void
cp2dp_mpls_route_install (node_t *node,
                         mpls_label_val_t in_label,
                         c_string gw_ip,
                         uint32_t ifindex,
                         mpls_label_val_t (*label_stack)[MAX_LBL_DEPTH],
                         uint8_t label_stack_count) {
    
    dp_msg_t *dp_msg;
    mpls_route_update_msg_t *mpls_update_msg;
    
    dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = MPLS_TABLE;
    dp_msg->opr_type = DP_CREATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(mpls_route_update_msg_t);
    mpls_update_msg = (mpls_route_update_msg_t *)dp_msg->data;
    
    mpls_update_msg->in_label = in_label;
    mpls_update_msg->ifindex = ifindex;
    mpls_update_msg->gw_ip = tcp_ip_convert_ip_p_to_n (gw_ip);
    mpls_update_msg->label_stack_count = label_stack_count;
    
    /* Copy label stack - labels are already encoded using set_label_value() */
    if (label_stack && label_stack_count > 0) {
        for (int i = 0; i < label_stack_count && i < MAX_LBL_DEPTH; i++) {
            mpls_update_msg->label_stack[i].label_val = (*label_stack)[i];
            mpls_update_msg->label_stack[i].op = MPLS_OP_PUSH;
        }
    }
    
    cp2dp_submit(node, dp_msg, true);
}

/* Wrapper fn to delete MPLS route Asynchronously (removes all nexthops) */
void
cp2dp_mpls_route_delete (node_t *node, mpls_label_val_t in_label) {
    
    dp_msg_t *dp_msg;
    mpls_route_update_msg_t *mpls_update_msg;
    
    dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = MPLS_TABLE;
    dp_msg->opr_type = DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(mpls_route_update_msg_t);
    mpls_update_msg = (mpls_route_update_msg_t *)dp_msg->data;
    
    /* Only in_label is needed for full route deletion */
    mpls_update_msg->in_label = in_label;
    mpls_update_msg->ifindex = 0;
    mpls_update_msg->gw_ip = 0;
    mpls_update_msg->label_stack_count = 0;
    
    cp2dp_submit(node, dp_msg, true);
}

/* Wrapper fn to delete specific MPLS nexthop Asynchronously */
void
cp2dp_mpls_nexthop_delete (node_t *node,
                           mpls_label_val_t in_label,
                           c_string gw_ip,
                           uint32_t ifindex,
                           mpls_label_val_t (*label_stack)[MAX_LBL_DEPTH],
                           uint8_t label_stack_count) {
    
    dp_msg_t *dp_msg;
    mpls_route_update_msg_t *mpls_update_msg;
    
    dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = MPLS_TABLE;
    dp_msg->opr_type = DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(mpls_route_update_msg_t);
    mpls_update_msg = (mpls_route_update_msg_t *)dp_msg->data;
    
    /* Populate nexthop details for specific deletion */
    mpls_update_msg->in_label = in_label;
    mpls_update_msg->ifindex = ifindex;
    mpls_update_msg->gw_ip = tcp_ip_convert_ip_p_to_n(gw_ip);
    mpls_update_msg->label_stack_count = label_stack_count;
    
    /* Copy label stack - labels are already encoded */
    if (label_stack && label_stack_count > 0) {
        for (int i = 0; i < label_stack_count && i < MAX_LBL_DEPTH; i++) {
            mpls_update_msg->label_stack[i].label_val = (*label_stack)[i];
            mpls_update_msg->label_stack[i].op = MPLS_OP_PUSH;
        }
    }
    
    cp2dp_submit(node, dp_msg, true);
}

/* Data plane handler for IPv4 MPLS table messages */
static void
dp_ipv4_mpls_table_process_msg(node_t *node, dp_msg_t *dp_msg) {
    
    ipv4_mpls_route_update_msg_t *ipv4_mpls_update_msg;
    nexthop_t *nexthop;
    mpls_lstack_t *lstack;
    Interface *oif;
    char ip_addr_str[IPV4_ADDR_LEN_STR];
    char prefix_str[IPV4_ADDR_LEN_STR];
    rt_table_t *ipv4_mpls_rt_table = NODE_IPV4_MPLS_RT_TABLE(node);
    l3_route_t *l3_route;
    bool new_route = false;
    labelled_nxthop_proto_id_t nh_proto = lbl_proto_nxthop_static;

    assert(dp_msg->component_type == IPV4_MPLS_TABLE);
    
    switch (dp_msg->opr_type) {
        
        case DP_CREATE:
            ipv4_mpls_update_msg = (ipv4_mpls_route_update_msg_t *)dp_msg->data;
            
            /* Convert prefix to string */
            tcp_ip_covert_ip_n_to_p(ipv4_mpls_update_msg->prefix, (c_string)prefix_str);
            
            /* Get the interface */
            oif = node_get_intf_by_ifindex(node, ipv4_mpls_update_msg->ifindex);
            if (!oif) {
                tracer (node->dptr, DMPLS | DERR, 
                       "IPv4 MPLS RIB : Interface with index %d not found\n", 
                       ipv4_mpls_update_msg->ifindex);
                cp2dp_msg_free(dp_msg);
                return;
            }
            
            /* Lookup existing route */
            l3_route = rt_table_lookup_exact_match(ipv4_mpls_rt_table, 
                                                   (c_string)prefix_str, 
                                                   ipv4_mpls_update_msg->mask);
            
            if (!l3_route) {
                /* Create new route */
                l3_route = l3_route_get_new_route();
                string_copy((char *)l3_route->dest, prefix_str, 16);
                l3_route->dest[15] = '\0';
                l3_route->mask = ipv4_mpls_update_msg->mask;
                l3_route->is_direct = false;
                l3_route->nh_count = 0;
                new_route = true;
            }
            
            /* Create nexthop */
            nexthop = nh_create_new_nexthop(
                (c_string)node->node_name,
                ipv4_mpls_update_msg->ifindex,
                tcp_ip_covert_ip_n_to_p (ipv4_mpls_update_msg->gw_ip, (c_string)ip_addr_str),
                PROTO_STATIC);
            
            if (!nexthop) {
                tracer (node->dptr, DMPLS | DERR, 
                       "IPv4 MPLS RIB : Failed to create nexthop\n");
                if (new_route) l3_route_free(l3_route);
                cp2dp_msg_free(dp_msg);
                return;
            }
            
            nexthop->oif = oif->GetSharedPtr();
            
            /* Create and populate label stack if labels are provided */
            if (ipv4_mpls_update_msg->label_stack_count > 0) {
                lstack = (mpls_lstack_t *)XCALLOC2(0, 1, mpls_lstack_t);
                lstack->curr_index = 0;
                
                for (int i = 0; i < ipv4_mpls_update_msg->label_stack_count && i < MAX_LBL_DEPTH; i++) {
                    lstack->labels[i].label_val = ipv4_mpls_update_msg->label_stack[i].label_val;
                    lstack->labels[i].op = ipv4_mpls_update_msg->label_stack[i].op;
                }
                
                nexthop->lbls = lstack;
            }
            
            /* Check for duplicate nexthop */
            if (!new_route) {
                if (nh_is_nexthop_exist_in_nh_array(l3_route->nexthops[nh_proto], nexthop)) {
                    tracer (node->dptr, DMPLS | DERR, 
                           "IPv4 MPLS RIB : Duplicate nexthop for route %s/%d\n",
                           prefix_str, ipv4_mpls_update_msg->mask);
                    nexthop_dereference(nexthop);
                    cp2dp_msg_free(dp_msg);
                    return;
                }
            }
            
            /* Add nexthop to route */
            if (!nh_insert_new_nexthop_nh_array(l3_route->nexthops[nh_proto], nexthop)) {
                tracer (node->dptr, DMPLS | DERR, 
                       "IPv4 MPLS RIB : Failed to add nexthop to route %s/%d\n",
                       prefix_str, ipv4_mpls_update_msg->mask);
                nexthop_dereference(nexthop);
                if (new_route) l3_route_free(l3_route);
                cp2dp_msg_free(dp_msg);
                return;
            }
            
            l3_route->nh_count++;
            
            /* If new route, install in routing table */
            if (new_route) {
                if (!_rt_table_entry_add(ipv4_mpls_rt_table, l3_route)) {
                    tracer (node->dptr, DMPLS | DERR, 
                           "IPv4 MPLS RIB : Failed to install route %s/%d\n",
                           prefix_str, ipv4_mpls_update_msg->mask);
                    nexthop_dereference(nexthop);
                    l3_route_free(l3_route);
                    cp2dp_msg_free(dp_msg);
                    return;
                }
            }
            
            tracer (node->dptr, DMPLS, 
                   "IPv4 MPLS RIB : Route %s/%d installed successfully - gw=%s, oif=%s\n",
                   prefix_str, ipv4_mpls_update_msg->mask,
                   ip_addr_str, oif->if_name.c_str());
            
            break;
            
        case DP_DEL:
        {
            ipv4_mpls_update_msg = (ipv4_mpls_route_update_msg_t *)dp_msg->data;
            
            /* Convert prefix to string */
            tcp_ip_covert_ip_n_to_p(ipv4_mpls_update_msg->prefix, (c_string)prefix_str);
            
            /* Lookup the route */
            l3_route = rt_table_lookup_exact_match(ipv4_mpls_rt_table, 
                                                   (c_string)prefix_str, 
                                                   ipv4_mpls_update_msg->mask);
            
            if (!l3_route) {
                tracer (node->dptr, DMPLS | DERR, 
                       "IPv4 MPLS RIB : Route %s/%d not found, deletion failed\n",
                       prefix_str, ipv4_mpls_update_msg->mask);
                cp2dp_msg_free(dp_msg);
                return;
            }
            
            /* Check if specific nexthop deletion or full route deletion */
            if (ipv4_mpls_update_msg->gw_ip != 0 && ipv4_mpls_update_msg->ifindex != 0) {
                /* Specific nexthop deletion */
                
                /* Get interface */
                oif = node_get_intf_by_ifindex(node, ipv4_mpls_update_msg->ifindex);
                if (!oif) {
                    tracer (node->dptr, DMPLS | DERR, 
                           "IPv4 MPLS RIB : Interface with index %d not found for nexthop deletion\n", 
                           ipv4_mpls_update_msg->ifindex);
                    cp2dp_msg_free(dp_msg);
                    return;
                }
                
                /* Create temporary nexthop for comparison */
                nexthop = nh_create_new_nexthop(
                    (c_string)node->node_name,
                    ipv4_mpls_update_msg->ifindex,
                    tcp_ip_covert_ip_n_to_p(ipv4_mpls_update_msg->gw_ip, (c_string)ip_addr_str),
                    PROTO_STATIC);
                
                nexthop->oif = oif->GetSharedPtr();
                
                /* Create label stack if provided */
                if (ipv4_mpls_update_msg->label_stack_count > 0) {
                    lstack = (mpls_lstack_t *)XCALLOC2(0, 1, mpls_lstack_t);
                    lstack->curr_index = 0;
                    
                    for (int i = 0; i < ipv4_mpls_update_msg->label_stack_count && i < MAX_LBL_DEPTH; i++) {
                        lstack->labels[i].label_val = ipv4_mpls_update_msg->label_stack[i].label_val;
                        lstack->labels[i].op = ipv4_mpls_update_msg->label_stack[i].op;
                    }
                    
                    nexthop->lbls = lstack;
                }
                
                /* Remove specific nexthop */
                if (nh_remove_nexthop_from_nh_array(l3_route->nexthops[nh_proto], nexthop)) {
                    l3_route->nh_count--;
                    tracer (node->dptr, DMPLS, 
                           "IPv4 MPLS RIB : Nexthop removed from route %s/%d\n",
                           prefix_str, ipv4_mpls_update_msg->mask);
                } else {
                    tracer (node->dptr, DMPLS | DERR, 
                           "IPv4 MPLS RIB : Nexthop not found in route %s/%d\n",
                           prefix_str, ipv4_mpls_update_msg->mask);
                }
                
                /* Clean up temporary nexthop */
                nexthop_dereference(nexthop);
                
            } else {
                /* Full route deletion - remove route from table along with all nexthops */
                
                /* Flush all nexthops from all protocol types */
                labelled_nxthop_proto_id_t proto;
                FOR_ALL_LABELLED_NXTHOP_PROTO(proto) {
                    int count = nh_flush_nexthops(l3_route->nexthops[proto]);
                    l3_route->nh_count -= count;
                }
                
                /* Delete the route from the mtrie routing table */
                uint32_t bin_ip, bin_mask;
                bitmap_t prefix_bm, mask_bm;
                
                bin_ip = ipv4_mpls_update_msg->prefix;
                bin_ip = htonl(bin_ip);
                bin_mask = tcp_ip_convert_dmask_to_bin_mask(ipv4_mpls_update_msg->mask);
                bin_mask = ~bin_mask;
                bin_mask = htonl(bin_mask);
                
                bitmap_init(&prefix_bm, 32);
                bitmap_init(&mask_bm, 32);
                
                prefix_bm.bits[0] = bin_ip;
                mask_bm.bits[0] = bin_mask;
                
                assert(mtrie_delete_prefix(&ipv4_mpls_rt_table->route_list,
                                          &prefix_bm,
                                          &mask_bm,
                                          (void **)&l3_route) == MTRIE_DELETE_SUCCESS);
                
                bitmap_free_internal(&prefix_bm);
                bitmap_free_internal(&mask_bm);
                
                tracer (node->dptr, DMPLS, 
                       "IPv4 MPLS RIB : Route %s/%d deleted successfully\n",
                       prefix_str, ipv4_mpls_update_msg->mask);
                
                /* Decrement reference count to free the route */
                l3_route_dec_ref_count(l3_route);
            }
            
            break;
        }
            
        case DP_UPDATE:
            /* TODO: Implement IPv4 MPLS route update if needed */
            break;
            
        case DP_READ:
            /* TODO: Implement IPv4 MPLS table reads if needed */
            break;
            
        default:
            break;
    }
    
    cp2dp_msg_free(dp_msg);
}

/* Wrapper fn to install IPv4 MPLS route Asynchronously */
void
cp2dp_ipv4_mpls_route_install (node_t *node,
                               c_string prefix,
                               uint8_t mask,
                               c_string gw_ip,
                               uint32_t ifindex,
                               mpls_label_val_t (*label_stack)[MAX_LBL_DEPTH],
                               uint8_t label_stack_count) {
    
    dp_msg_t *dp_msg;
    ipv4_mpls_route_update_msg_t *ipv4_mpls_update_msg;
    
    dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = IPV4_MPLS_TABLE;
    dp_msg->opr_type = DP_CREATE;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(ipv4_mpls_route_update_msg_t);
    ipv4_mpls_update_msg = (ipv4_mpls_route_update_msg_t *)dp_msg->data;
    
    ipv4_mpls_update_msg->prefix = tcp_ip_convert_ip_p_to_n(prefix);
    ipv4_mpls_update_msg->mask = mask;
    ipv4_mpls_update_msg->gw_ip = tcp_ip_convert_ip_p_to_n(gw_ip);
    ipv4_mpls_update_msg->ifindex = ifindex;
    ipv4_mpls_update_msg->label_stack_count = label_stack_count;
    
    /* Copy label stack - labels are already encoded using set_label_value() */
    if (label_stack && label_stack_count > 0) {
        for (int i = 0; i < label_stack_count && i < MAX_LBL_DEPTH; i++) {
            ipv4_mpls_update_msg->label_stack[i].label_val = (*label_stack)[i];
            ipv4_mpls_update_msg->label_stack[i].op = MPLS_OP_PUSH;
        }
    }
    
    cp2dp_submit(node, dp_msg, true);
}

/* Wrapper fn to delete IPv4 MPLS route Asynchronously (removes all nexthops) */
void
cp2dp_ipv4_mpls_route_delete (node_t *node,
                              c_string prefix,
                              uint8_t mask) {
    
    dp_msg_t *dp_msg;
    ipv4_mpls_route_update_msg_t *ipv4_mpls_update_msg;
    
    dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = IPV4_MPLS_TABLE;
    dp_msg->opr_type = DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(ipv4_mpls_route_update_msg_t);
    ipv4_mpls_update_msg = (ipv4_mpls_route_update_msg_t *)dp_msg->data;
    
    /* Set prefix and mask for route deletion */
    ipv4_mpls_update_msg->prefix = tcp_ip_convert_ip_p_to_n(prefix);
    ipv4_mpls_update_msg->mask = mask;
    ipv4_mpls_update_msg->ifindex = 0;
    ipv4_mpls_update_msg->gw_ip = 0;
    ipv4_mpls_update_msg->label_stack_count = 0;
    
    cp2dp_submit(node, dp_msg, true);
}

/* Wrapper fn to delete specific IPv4 MPLS nexthop Asynchronously */
void
cp2dp_ipv4_mpls_nexthop_delete (node_t *node,
                                c_string prefix,
                                uint8_t mask,
                                c_string gw_ip,
                                uint32_t ifindex,
                                mpls_label_val_t (*label_stack)[MAX_LBL_DEPTH],
                                uint8_t label_stack_count) {
    
    dp_msg_t *dp_msg;
    ipv4_mpls_route_update_msg_t *ipv4_mpls_update_msg;
    
    dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = IPV4_MPLS_TABLE;
    dp_msg->opr_type = DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(ipv4_mpls_route_update_msg_t);
    ipv4_mpls_update_msg = (ipv4_mpls_route_update_msg_t *)dp_msg->data;
    
    /* Populate route and nexthop details for specific deletion */
    ipv4_mpls_update_msg->prefix = tcp_ip_convert_ip_p_to_n(prefix);
    ipv4_mpls_update_msg->mask = mask;
    ipv4_mpls_update_msg->gw_ip = tcp_ip_convert_ip_p_to_n(gw_ip);
    ipv4_mpls_update_msg->ifindex = ifindex;
    ipv4_mpls_update_msg->label_stack_count = label_stack_count;
    
    /* Copy label stack - labels are already encoded */
    if (label_stack && label_stack_count > 0) {
        for (int i = 0; i < label_stack_count && i < MAX_LBL_DEPTH; i++) {
            ipv4_mpls_update_msg->label_stack[i].label_val = (*label_stack)[i];
            ipv4_mpls_update_msg->label_stack[i].op = MPLS_OP_PUSH;
        }
    }
    
    cp2dp_submit(node, dp_msg, true);
}

void
cp2dp_fib_update (
        node_t *node,
        uint8_t target_fib_vrf_id,
        AFI_T target_fib_afi,
        cmn_prefix_t *prefix,
        uint32_t nh_idx,
         uint32_t inh_idx,
        rtm_nh_fwd_info_t *fwd_info,
        FIB_OPN_T operation) {

    dp_msg_t *dp_msg = cp2dp_msg_alloc ();
    fib_update_msg_t *msg = (fib_update_msg_t *)dp_msg->data;

    /* Set message metadata */
    dp_msg->component_type = FIB_TABLE;
    dp_msg->opr_type = (operation == FIB_ADD) ? DP_CREATE : DP_DEL;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(fib_update_msg_t);

    /* Populate FIB update message */
    msg->target_fib_vrf_id = target_fib_vrf_id;
    msg->target_fib_afi = target_fib_afi;
    msg->fwd_flags = fwd_info ? fwd_info->fwd_flags : 0;
    msg->nhidx = nh_idx;
    msg->inhidx = inh_idx;
    msg->prefix = *prefix;

    if (fwd_info) memcpy(&msg->fwd_info, fwd_info, sizeof(fib_nh_fwd_info_t));    

    /* Submit to data plane */
    cp2dp_submit(node, dp_msg, true);
}
