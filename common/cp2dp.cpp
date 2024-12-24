#include <assert.h>
#include "../graph.h"
#include "l3_hdrs.h"
#include "cp2dp.h"
#include "../EventDispatcher/event_dispatcher.h"
#include "../dpdk/layer3/dp_rtm.h"
#include "../Layer3/layer3.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../pkt_block.h"
#include "../Interface/InterfaceUApi.h"
#include "../Tracer/tracer.h"
#include "../Layer3/ipv6/ipv6_hdrs.h"

extern void
np_tcp_ip_send_ip6_data (node_t *node, pkt_block_t *pkt_block);

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
        case PKT_BLOCK:
            np_recv_cp_pkt_block (node, dp_msg);
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

    if (!pkt_block) {
        pkt_block = pkt_block_get_new_pkt_buffer(sizeof(ip_hdr_t));
    }
    else {
        pkt_block_expand_buffer_left (pkt_block, sizeof (ip_hdr_t));
    }

    pkt_block_set_starting_hdr_type (pkt_block, IP_HDR);

    ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr(pkt_block);
    pkt_size_t pkt_size = pkt_block->pkt_size;

    initialize_ip_hdr (ip_hdr);

    ip_hdr->protocol = std_ip_protocol;
    ip_hdr->src_ip = tcp_ip_convert_ip_p_to_n(NODE_LO_ADDR(node));
    ip_hdr->dst_ip = dest_ip_addr;
    ip_hdr->total_length = 
        IP_HDR_COMPUTE_DEFAULT_TOTAL_LEN((pkt_size - sizeof (ip_hdr_t)));
    dp_msg_t *dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = PKT_BLOCK;
    dp_msg->opr_type = DP_L3_NORTHBOUND_IN;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(pkt_block_t *);
    memcpy (dp_msg->data, &pkt_block, sizeof(pkt_block_t *));
    pkt_block_reference(pkt_block);
    cp2dp_submit (node, dp_msg, true);
}

/* Write the ipv6 equivalent function of cp2dp_send_ip_data( )*/
void 
cp2dp_send_ip6_data ( node_t *node, 
                                    pkt_block_t *pkt_block,
                                    ipv6_addr_t dest_ip_addr,
                                    uint16_t std_ip_protocol) 
{
    pkt_size_t ipv6_payload_size = 0;

    if (!pkt_block) {
        pkt_block = pkt_block_get_new_pkt_buffer(sizeof(ipv6_hdr_t));
    }
    else {
        ipv6_payload_size = pkt_block->pkt_size;
        pkt_block_expand_buffer_left (pkt_block, sizeof (ipv6_hdr_t));
    }

    pkt_block_set_starting_hdr_type (pkt_block, IP6_HDR);

    pkt_size_t pkt_size;
    ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)pkt_block_get_pkt (pkt_block, &pkt_size);

    initialize_ipv6_hdr (ipv6_hdr);

    ipv6_hdr->next_header = std_ip_protocol;
    ipv6_hdr->payload_length =  ipv6_payload_size;
    memcpy (ipv6_hdr->dst_addr, dest_ip_addr.addr, 16);

    dp_msg_t *dp_msg = cp2dp_msg_alloc ();
    dp_msg->component_type = PKT_BLOCK;
    dp_msg->opr_type = DP_L3_NORTHBOUND_IN;
    dp_msg->flags = 0;
    dp_msg->data_size = sizeof(pkt_block_t *);
    memcpy (dp_msg->data, &pkt_block, sizeof(pkt_block_t *));
    pkt_block_reference(pkt_block);
    cp2dp_submit (node, dp_msg, true);
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
                                uint8_t srv6_flavor,
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
    rt_update_msg->srv6_flavor = srv6_flavor;
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