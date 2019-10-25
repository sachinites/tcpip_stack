#include "hello.h"
#include "WheelTimer/WheelTimer.h"
#include <stdio.h>
#include "comm.h"
#include "net.h"

typedef struct pkt_meta_data_{

    interface_t *intf;
    char *pkt;
    unsigned int pkt_size;
} pkt_meta_data_t;

static void 
transmit_hellos(void *arg, int sizeof_arg){

    pkt_meta_data_t *pkt_meta_data = (pkt_meta_data_t *)arg;
    send_pkt_out(pkt_meta_data->pkt, pkt_meta_data->pkt_size,
            pkt_meta_data->intf);
#if 0
    printf("Hello sent out of interface : (%s)%s\n", 
            pkt_meta_data->intf->att_node->node_name, 
            pkt_meta_data->intf->if_name);
#endif
    pkt_meta_data->intf->intf_nw_props.hellos_sent++;
}

ethernet_hdr_t *
get_new_hello_pkt(node_t *node,
               	 interface_t *interface,
		 unsigned int *pkt_size){

    ethernet_hdr_t *hello = calloc(1, MAX_PACKET_BUFFER_SIZE);
    memcpy(hello->src_mac.mac, IF_MAC(interface), sizeof(mac_add_t));
    layer2_fill_with_broadcast_mac(hello->dst_mac.mac);
    hello->type = HELLO_MSG_CODE;
    
    hello_t *hello_payload = (hello_t *)GET_ETHERNET_HDR_PAYLOAD(hello);
    memcpy(hello_payload->router_name, node->node_name, NODE_NAME_SIZE);
    memcpy(hello_payload->router_id, NODE_LO_ADDR(node), 16);
    memcpy(hello_payload->intf_ip, IF_IP(interface), 16);
    ETH_FCS(hello, sizeof(hello_t)) = 0;

    *pkt_size = GET_ETH_HDR_SIZE_EXCL_PAYLOAD(hello) + sizeof(hello_t);
    
    return (ethernet_hdr_t *)(pkt_buffer_shift_right(
		(char *)hello, *pkt_size, 
		 MAX_PACKET_BUFFER_SIZE));
}

bool_t
schedule_hello_on_interface(interface_t *intf,
                            int interval_sec, bool_t is_repeat){

    unsigned int pkt_size = 0;

    if(is_hellos_scheduled_on_intf(intf))
        return FALSE;

    node_t *node = intf->att_node;
   
    ethernet_hdr_t *hello_pkt = get_new_hello_pkt(node, intf, &pkt_size); 
    
    pkt_meta_data_t pkt_meta_data;
    pkt_meta_data.intf = intf;
    pkt_meta_data.pkt = (char *)hello_pkt;
    pkt_meta_data.pkt_size = pkt_size;

    wheel_timer_elem_t *wt_elem = register_app_event(GET_NODE_TIMER_FROM_INTF(intf),
                                                     transmit_hellos,
                                                     (void *)&pkt_meta_data,
                                                     sizeof(pkt_meta_data_t),
                                                     interval_sec,
                                                     is_repeat ? 1 : 0);
    intf->intf_nw_props.hellos = wt_elem;

    if(is_hellos_scheduled_on_intf(intf))
        return TRUE;

    return FALSE;
}

void
stop_interface_hellos(interface_t *interface){

    if(!is_hellos_scheduled_on_intf(interface))
        return;

    wheel_timer_elem_t *wt_elem = interface->intf_nw_props.hellos;
    pkt_meta_data_t *pkt_meta_data = (pkt_meta_data_t *)wt_elem->arg;
    free(pkt_meta_data->pkt - MAX_PACKET_BUFFER_SIZE + pkt_meta_data->pkt_size);
    de_register_app_event(wt_elem);
    interface->intf_nw_props.hellos = NULL;
}

static void
update_interface_adjacency_from_hello(interface_t *interface,
                                       hello_t *hello){

    adjacency_t *adjacency = interface->intf_nw_props.adjacency;
    if(!adjacency){
        adjacency = (adjacency_t *)calloc(1, sizeof(adjacency_t));
        interface->intf_nw_props.adjacency = adjacency;
    }
    memcpy(adjacency->router_name, hello->router_name, NODE_NAME_SIZE);
    memcpy(adjacency->router_id, hello->router_id, 16);
    memcpy(adjacency->nbr_ip, hello->intf_ip, 16);
    interface->intf_nw_props.hellos_recv++;
}

void
process_hello_msg(interface_t *iif, ethernet_hdr_t *hello_eth_hdr){

	/*Reject the pkt if dst mac is not Brodcast mac*/
    if(!IS_MAC_BROADCAST_ADDR(hello_eth_hdr->dst_mac.mac)){
        goto del_adj;
	}

    /* Reject hello if ip_address in hello do not lies in same subnet as
     * reciepient interface*/
    hello_t *hello = (hello_t *)GET_ETHERNET_HDR_PAYLOAD(hello_eth_hdr);

    if(!is_same_subnet(IF_IP(iif), 
                       iif->intf_nw_props.mask, 
                       hello->intf_ip)){
        goto del_adj;
    }

    update_interface_adjacency_from_hello(iif, hello);
    return ;

    del_adj:
        delete_interface_adjacency(iif);
        iif->intf_nw_props.bad_hellos_recv++;
}

void
dump_interface_adjacencies(interface_t *interface){

    adjacency_t *adjacency = interface->intf_nw_props.adjacency;
    if(!adjacency)
        return;

    printf("\t\t Adjacency : Nbr Name : %s, Router id : %s, nbr ip : %s\n",
            adjacency->router_name, adjacency->router_id, adjacency->nbr_ip);
}

void
delete_interface_adjacency(interface_t *interface){

    adjacency_t *adjacency = interface->intf_nw_props.adjacency;
    if(!adjacency)
        return;
    free(adjacency);
    interface->intf_nw_props.adjacency = NULL;
}
