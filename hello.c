#include "hello.h"
#include "WheelTimer/WheelTimer.h"
#include <stdio.h>
#include "comm.h"
#include "net.h"

#define ADJ_DEF_EXPIRY_TIMER    3

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
    de_register_app_event(GET_NODE_TIMER_FROM_INTF(interface), wt_elem);
    interface->intf_nw_props.hellos = NULL;
}

static void
update_interface_adjacency_from_hello(interface_t *interface,
                                      hello_t *hello){

    bool_t new_adj = FALSE;
    adjacency_t *adjacency = NULL;

    adjacency = find_adjacency_on_interface(interface, hello->router_id);

    if(!adjacency){
        adjacency = (adjacency_t *)calloc(1, sizeof(adjacency_t));
        init_glthread(&adjacency->glue);
        time(&adjacency->uptime);
        glthread_add_next(GET_INTF_ADJ_LIST(interface), &adjacency->glue);
        new_adj = TRUE;
    }
    memcpy(adjacency->router_name, hello->router_name, NODE_NAME_SIZE);
    memcpy(adjacency->router_id, hello->router_id, 16);
    memcpy(adjacency->nbr_ip, hello->intf_ip, 16);
    if(new_adj)
        adjacency_start_expiry_timer(interface, adjacency);
    else
        adjacency_refresh_expiry_timer(interface, adjacency);
    interface->intf_nw_props.hellos_recv++;
}

void
process_hello_msg(interface_t *iif, ethernet_hdr_t *hello_eth_hdr){

	/*Reject the pkt if dst mac is not Brodcast mac*/
    if(!IS_MAC_BROADCAST_ADDR(hello_eth_hdr->dst_mac.mac)){
        goto bad_hello;
	}

    /* Reject hello if ip_address in hello do not lies in same subnet as
     * reciepient interface*/
    hello_t *hello = (hello_t *)GET_ETHERNET_HDR_PAYLOAD(hello_eth_hdr);

    if(!is_same_subnet(IF_IP(iif), 
                       iif->intf_nw_props.mask, 
                       hello->intf_ip)){
        goto bad_hello;
    }

    update_interface_adjacency_from_hello(iif, hello);
    return ;

    bad_hello:
        iif->intf_nw_props.bad_hellos_recv++;
}

void
dump_interface_adjacencies(interface_t *interface){

    glthread_t *curr;
    adjacency_t *adjacency;
    time_t curr_time;

    curr_time = time(NULL);
    ITERATE_GLTHREAD_BEGIN(GET_INTF_ADJ_LIST(interface), curr){
        
        adjacency = glthread_to_adjacency(curr);
        printf("\t\t Adjacency : Nbr Name : %s, Router id : %s,"
               " nbr ip : %s, Expires in : %d sec, uptime = %s\n",
                adjacency->router_name, 
                adjacency->router_id, 
                adjacency->nbr_ip, 
                wt_get_remaining_time(GET_NODE_TIMER_FROM_INTF(interface),
                adjacency->expiry_timer),
                hrs_min_sec_format(
                    (unsigned int)difftime(curr_time, adjacency->uptime)));
    } ITERATE_GLTHREAD_END(GET_INTF_ADJ_LIST(interface), curr);    
}

/* Delete all interface adj if router_id is NULL, else
 * delete only particular adj*/
void
delete_interface_adjacency(interface_t *interface, 
                            char *router_id){
                            

    adjacency_t *adjacency = NULL;
    
    if(router_id){

        adjacency = find_adjacency_on_interface(interface, router_id);
        if(!adjacency) return;
        remove_glthread(&adjacency->glue);
        adjacency_delete_expiry_timer(interface, adjacency);
        free(adjacency);
        return;
    }

    glthread_t *curr;
    ITERATE_GLTHREAD_BEGIN(GET_INTF_ADJ_LIST(interface), curr){

        adjacency = glthread_to_adjacency(curr);  
        remove_glthread(&adjacency->glue);
        adjacency_delete_expiry_timer(interface, adjacency);
        free(adjacency);
    }ITERATE_GLTHREAD_END(GET_INTF_ADJ_LIST(interface), curr);
}

adjacency_t *
find_adjacency_on_interface(interface_t *interface, char *router_id){

    glthread_t *curr;
    adjacency_t *adjacency;

    ITERATE_GLTHREAD_BEGIN(GET_INTF_ADJ_LIST(interface), curr){

        adjacency = glthread_to_adjacency(curr);
        if(strncmp(adjacency->router_id, router_id, 16) == 0)
            return adjacency;
    } ITERATE_GLTHREAD_END(GET_INTF_ADJ_LIST(interface), curr);
    return NULL;
}

/*Adjacency Timers*/

typedef struct adj_key_{

    interface_t *interface;
    char nbr_rtr_id[16];
} adj_key_t;

static void
set_adjacency_key(interface_t *interface, 
                  adjacency_t *adjacency, 
                  adj_key_t *adj_key){

    memset(adj_key, 0, sizeof(adj_key_t));
    adj_key->interface = interface;
    memcpy(adj_key->nbr_rtr_id, adjacency->router_id, 16);
}


void
adjacency_delete_expiry_timer(interface_t *interface, adjacency_t *adjacency){

    assert(adjacency->expiry_timer);
    de_register_app_event(GET_NODE_TIMER_FROM_INTF(interface), 
                    adjacency->expiry_timer);
    adjacency->expiry_timer = NULL;
}

void
adjacency_refresh_expiry_timer(interface_t *interface,
        adjacency_t *adjacency){

    wheel_timer_elem_t *wt_elem = 
        adjacency->expiry_timer;
    
    assert(wt_elem);

    wt_elem_reschedule(GET_NODE_TIMER_FROM_INTF(interface),
                        wt_elem, ADJ_DEF_EXPIRY_TIMER);
}

static void
timer_expire_delete_adjacency_cb(void *arg, int sizeof_arg){

    adj_key_t *adj_key = (adj_key_t *)arg;
    delete_interface_adjacency(adj_key->interface, 
                               adj_key->nbr_rtr_id); 
}


void
adjacency_start_expiry_timer(interface_t *interface,
        adjacency_t *adjacency){

    if(adjacency->expiry_timer){
        adjacency_delete_expiry_timer(interface, adjacency);
    }

    adj_key_t adj_key;
    set_adjacency_key(interface, adjacency, &adj_key);

    adjacency->expiry_timer = register_app_event(GET_NODE_TIMER_FROM_INTF(interface),
                                    timer_expire_delete_adjacency_cb,
                                    (void *)&adj_key, sizeof(adj_key_t),
                                    ADJ_DEF_EXPIRY_TIMER,
                                    0);
    if(!adjacency->expiry_timer){
        printf("Error : Expiry timer for Adjacency : %s, %s, %s could not be started\n",
            interface->att_node->node_name, interface->if_name, adjacency->router_name);
    }
}

