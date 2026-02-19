#include "../../pkt_block.h"
#include "dp_intf.h"
#include "../../FireWall/acl/acldb.h"
#include "../../Tracer/tracer.h"

typedef int (*SendPacketOut_fptr)(dp_intf_t *, pkt_block_t *);

extern bool LinuxRtr;

static int
send_xmit_out (dp_intf_t *interface, pkt_block_t *pkt_block)
{
    pkt_size_t pkt_size;
    ev_dis_pkt_data_t *ev_dis_pkt_data;
    node_t *sending_node = interface->att_node;

    uint8_t *pkt = pkt_block_get_pkt(pkt_block, &pkt_size);

    if (!(interface->is_up))
    {
        interface->xmit_pkt_dropped++;
        return 0;
    }

    if (pkt_size > MAX_PACKET_BUFFER_SIZE)
    {
        cprintf("Error : Node :%s, Pkt Size exceeded\n", sending_node->node_name);
        return -1;
    }

    node_t *nbr_node = interface->nbr_intf->att_node;

    tracer (sending_node->dptr, DFLOW_DET, "Pkt : %s Wired out of interface %s\n", 
        pkt_block_str (pkt_block), interface->if_name);
    
    dp_intf_t *other_interface = interface->nbr_intf;

    ev_dis_pkt_data = new ev_dis_pkt_data_t;

    ev_dis_pkt_data->recv_node = nullptr;
    ev_dis_pkt_data->recv_intf = nullptr;
    ev_dis_pkt_data->recv_dp_intf = other_interface;
    ev_dis_pkt_data->pkt = tcp_ip_get_new_pkt_buffer(pkt_size);
    memcpy(ev_dis_pkt_data->pkt, pkt, pkt_size);
    ev_dis_pkt_data->pkt_size = pkt_size;

    //tcp_dump_send_logger(sending_node, interface,
     //                    pkt_block, pkt_block_get_starting_hdr(pkt_block));

    if (!pkt_q_enqueue(EV_DP(nbr_node), DP_PKT_Q(nbr_node),
                       (char *)ev_dis_pkt_data, sizeof(ev_dis_pkt_data_t)))
    {
        cprintf("%s : Fatal : Ingress Pkt QueueExhausted\n", nbr_node->node_name);
        tcp_ip_free_pkt_buffer(ev_dis_pkt_data->pkt, ev_dis_pkt_data->pkt_size);
        delete (ev_dis_pkt_data);
    }

    interface->pkt_sent++;
    return pkt_size;
}





static int 
PhysicalInterface_SendPacketOut(dp_intf_t *intf, pkt_block_t *pkt_block){

    if (intf->switchport)
    {
        //return SendPacketOutLAN(this, pkt_block);
    }
    else
    {
        return send_xmit_out(intf, pkt_block);
    }
}

static int 
VlanInterface_SendPacketOut(dp_intf_t *intf, pkt_block_t *pkt_block){

    return 0;
}

static int 
GRETunnelInterface_SendPacketOut(dp_intf_t *intf, pkt_block_t *pkt_block){

    return 0;
}

/* This array is arranged in sequence of these enums : InterfaceType_t */
static SendPacketOut_fptr intf_xmit_cbk[] = 
    {
        PhysicalInterface_SendPacketOut, 
        VlanInterface_SendPacketOut,
        GRETunnelInterface_SendPacketOut,
        0,
        0,
        0,
        0,
        0,
        0,
        0
    };

void 
dp_send_pkt_out (dp_intf_t *intf, pkt_block_t *pkt_block) {

    (intf_xmit_cbk[intf->if_type])(intf, pkt_block);
    return;
}