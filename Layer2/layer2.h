#ifndef __LAYER2__
#define __LAYER2__

#include "../net.h"
#include "../gluethread/glthread.h"
#include "../graph.h"
#include "../tcpconst.h"
#include <stdlib.h>

#define ARP_BROAD_REQ   1
#define ARP_REPLY       2
//define ARP_MSG         806
#define BROADCAST_MAC   0xFFFFFFFFFFFF
#define ETH_HDR_SIZE_EXCL_PAYLOAD (sizeof(ethernet_hdr_t) - sizeof(((ethernet_hdr_t *)0)->payload))
#define ETH_FCS(eth_hdr_ptr, payload_size) *((unsigned int *)(((ethernet_hdr_t *)eth_hdr_ptr -> payload) + payload_size))
#define IF_L2_MODE(interface_ptr) (interface_ptr->intf_nw_props.intf_l2_mode)
//define GET_ETHERNET_HDR_PAYLOAD(eth_hdr_ptr) ((char *)(eth_hdr_ptr -> payload))

#pragma pack (push,1)
typedef struct arp_hdr_{

    short hw_type;          /*1 for ethernet cable*/
    short proto_type;       /*0x0800 for IPV4*/
    char hw_addr_len;       /*6 for MAC*/
    char proto_addr_len;    /*4 for IPV4*/
    short op_code;          /*req or reply*/
    mac_add_t src_mac;      /*MAC of OIF interface*/
    unsigned int src_ip;        /*IP of OIF*/
    mac_add_t dst_mac;      /*?*/
    unsigned int dst_ip;        /*IP for which ARP is being resolved*/
} arp_hdr_t;

typedef struct ethernet_hdr_{

    mac_add_t dst_mac;
    mac_add_t src_mac;
    unsigned short type;
    char payload[248];  /*Max allowed 1500*/
    unsigned int FCS;
} ethernet_hdr_t;

#pragma pack(pop)

static inline ethernet_hdr_t *
ALLOC_ETH_HDR_WITH_PAYLOAD(char *pkt, unsigned int pkt_size){

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)(pkt - ETH_HDR_SIZE_EXCL_PAYLOAD);
    memset((char *)eth_hdr, 0, ETH_HDR_SIZE_EXCL_PAYLOAD);
    memcpy(eth_hdr->payload, pkt, pkt_size);
    return eth_hdr;

}


void
send_arp_broadcast_request(node_t *node, 
                           interface_t *oif, 
                           char *ip_addr);

/*ARP Table APIs*/
typedef struct arp_table_{

    glthread_t arp_entries;
} arp_table_t;

typedef struct arp_entry_{

    ip_add_t ip_addr;   /*key*/
    mac_add_t mac_addr;
    char oif_name[IF_NAME_SIZE];
    glthread_t arp_glue;

    bool_t is_sane;
    glthread_t arp_pending_list;
} arp_entry_t;
GLTHREAD_TO_STRUCT(arp_glue_to_arp_entry, arp_entry_t, arp_glue);
GLTHREAD_TO_STRUCT(arp_pending_list_to_arp_entry, arp_entry_t, arp_pending_list);



typedef struct arp_pending_entry_ arp_pending_entry_t;
typedef void (* arp_processing_fn)(node_t *, interface_t *, arp_entry_t *, arp_pending_entry_t *);
struct arp_pending_entry_{
    glthread_t arp_pending_entry_glue;
    arp_processing_fn cb;
    u_int32_t pkt_size; /* Includeing eth hdr */
    char pkt[0];

};
GLTHREAD_TO_STRUCT(arp_pending_entry_glue_to_arp_pending_entry, \
    arp_pending_entry_t, arp_pending_entry_glue);

#define IS_ARP_ENTRIES_EQUAL(arp_entry_1, arp_entry_2)  \
    (strncmp(arp_entry_1->ip_addr.ip_addr, arp_entry_2->ip_addr.ip_addr, IP_LEN) == 0 && \
        strncmp(arp_entry_1->mac_addr.mac, arp_entry_2->mac_addr.mac, MAC_LEN) == 0 && \
        strncmp(arp_entry_1->oif_name, arp_entry_2->oif_name, IF_NAME_SIZE) == 0 && \
        arp_entry_1->is_sane == arp_entry_2->is_sane &&     \
        arp_entry_1->is_sane == FALSE)
void
init_arp_table(arp_table_t **arp_table);

arp_entry_t *
arp_table_lookup(arp_table_t *arp_table, char *ip_addr);

void
clear_arp_table(arp_table_t *arp_table);

void
delete_arp_entry(arp_entry_t *arp_entry);
void
delete_arp_table_entry(arp_table_t *arp_table, char *ip_addr);

bool_t
arp_table_entry_add(arp_table_t *arp_table, arp_entry_t *arp_entry,
                    glthread_t **arp_pending_list);

void
dump_arp_table(arp_table_t *arp_table);

void
arp_table_update_from_arp_reply(arp_table_t *arp_table,
                                arp_hdr_t *arp_hdr, interface_t *iif);

static bool_t 
arp_entry_sane(arp_entry_t *arp_entry){

    return arp_entry->is_sane;
}

#pragma pack (push,1)
/*Vlan 802.1q 4 byte hdr*/
typedef struct vlan_8021q_hdr_{

    unsigned short tpid; /* = 0x8100*/
    short tci_pcp : 3 ;  /* inital 4 bits not used in this course*/
    short tci_dei : 1;   /*Not used*/
    short tci_vid : 12 ; /*Tagged vlan id*/
} vlan_8021q_hdr_t;

typedef struct vlan_ethernet_hdr_{

    mac_add_t dst_mac;
    mac_add_t src_mac;
    vlan_8021q_hdr_t vlan_8021q_hdr;
    unsigned short type;
    char payload[248];  /*Max allowed 1500*/
    unsigned int FCS;
} vlan_ethernet_hdr_t;
#pragma pack(pop)

//define VLAN_8021Q_PROTO 1
#define VLAN_ETH_FCS(vlan_eth_hdr_ptr, payload_size) *((unsigned int *)(((vlan_ethernet_hdr_t *)vlan_eth_hdr_ptr -> payload) + payload_size))
#define VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD (sizeof(vlan_ethernet_hdr_t) - sizeof(((vlan_ethernet_hdr_t *)0)->payload))
#define GET_COMMON_ETH_FCS(eth_hdr_ptr, payload_size) (is_pkt_vlan_tagged(ethernet_hdr) ? VLAN_ETH_FCS(ethernet_hdr, payload_size) \
                                                        : ETH_FCS(eth_hdr_ptr, payload_size))
static inline vlan_8021q_hdr_t *
is_pkt_vlan_tagged(ethernet_hdr_t *ethernet_hdr)
{
    char *ptr = (char *)ethernet_hdr + 2 * MAC_LEN;
    unsigned short value = *(unsigned short  *)ptr;
    if(value == VLAN_8021Q_PROTO)
        return (vlan_8021q_hdr_t *)((char *)ethernet_hdr + 2 * MAC_LEN);
    return NULL;
}

static inline unsigned int
GET_802_1Q_VLAN_ID(vlan_8021q_hdr_t *vlan_8021q_hdr)
{
    return vlan_8021q_hdr->tci_vid;
}

static inline char *
GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr_t *ethernet_hdr)
{
    if(is_pkt_vlan_tagged(ethernet_hdr))
        return (char *)(((vlan_ethernet_hdr_t *)ethernet_hdr) ->payload);
    return (char *)(ethernet_hdr ->payload);
}

static inline void
SET_COMMON_ETH_FCS(ethernet_hdr_t *ethernet_hdr,
                   unsigned int payload_size, unsigned int new_fcs)
{
    if(is_pkt_vlan_tagged(ethernet_hdr)){
        VLAN_ETH_FCS(ethernet_hdr, payload_size) = new_fcs;
    }
    else{
        ETH_FCS(ethernet_hdr, payload_size) = new_fcs;
    }       
    //GET_COMMON_ETH_FCS(ethernet_hdr, payload_size) = new_fcs;

}

static inline unsigned int GET_ETH_HDR_SIZE_EXCL_PAYLOAD(ethernet_hdr_t *ethernet_hdr){

    if(is_pkt_vlan_tagged(ethernet_hdr))
        return VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD;
    else
        return ETH_HDR_SIZE_EXCL_PAYLOAD;
}

static inline bool_t 
l2_frame_recv_qualify_on_interface(interface_t *interface, 
                                    ethernet_hdr_t *ethernet_hdr,
                                    unsigned int *output_vlan_id){

    *output_vlan_id = 0;

    vlan_8021q_hdr_t *vlan_8021q_hdr = 
                        is_pkt_vlan_tagged(ethernet_hdr);

    /* Presence of IP address on interface makes it work in L3 mode,
     * while absence of IP-address automatically make it work in
     * L2 mode provided that it is operational either in ACCESS mode or TRUNK mode.*/

    /* case 10 : If receiving interface is neither working in L3 mode
     * nor in L2 mode, then reject the packet*/
    if(!IS_INTF_L3_MODE(interface) &&
        IF_L2_MODE(interface) == L2_MODE_UNKNOWN){

        return FALSE;
    }

    /* If interface is working in ACCESS mode but at the
     * same time not operating within a vlan, then it must
     * accept untagged packet only*/

    if(IF_L2_MODE(interface) == ACCESS &&
        get_access_intf_operating_vlan_id(interface) == 0){

        if(!vlan_8021q_hdr)
            return FALSE;    /*case 3*/
        else
            return FALSE;   /*case 4*/
    }

    /* if interface is working in ACCESS mode and operating with in
     * vlan, then :
     * 1. it must accept untagged frame and tag it with a vlan-id of an interface
     * 2. Or  it must accept tagged frame but tagged with same vlan-id as interface's vlan operation*/

    unsigned int intf_vlan_id = 0,
                 pkt_vlan_id = 0;

    if(IF_L2_MODE(interface) == ACCESS){
        
        intf_vlan_id = get_access_intf_operating_vlan_id(interface);
            
        if(!vlan_8021q_hdr && intf_vlan_id){
            *output_vlan_id = intf_vlan_id;
            return TRUE; /*case 6*/
        }

        if(!vlan_8021q_hdr && !intf_vlan_id){
            /*case 3*/
            return TRUE;
        }

        pkt_vlan_id = GET_802_1Q_VLAN_ID(vlan_8021q_hdr);
        if(pkt_vlan_id == intf_vlan_id){
            return TRUE;    /*case 5*/
        }
        else{
            return FALSE;   /*case 5*/
        }
    }

    /* if interface is operating in a TRUNK mode, then it must discard all untagged
     * frames*/
    
    if(IF_L2_MODE(interface) == TRUNK){
       
        if(!vlan_8021q_hdr){
            /*case 7 & 8*/
            return FALSE;
        }
    }

    /* if interface is operating in a TRUNK mode, then it must accept the frame
     * which are tagged with any vlan-id in which interface is operating.*/

    if(IF_L2_MODE(interface) == TRUNK && 
            vlan_8021q_hdr){
        
        pkt_vlan_id = GET_802_1Q_VLAN_ID(vlan_8021q_hdr);
        if(is_trunk_interface_vlan_enabled(interface, pkt_vlan_id)){
            return TRUE;    /*case 9*/
        }
        else{
            return FALSE;   /*case 9*/
        }
    }
    
    /*If the interface is operating in L3 mode, and recv vlan tagged frame, drop it*/
    if(IS_INTF_L3_MODE(interface) && vlan_8021q_hdr){
        /*case 2*/
        return FALSE;
    }

    /* If interface is working in L3 mode, then accept the frame only when
     * its dst mac matches with receiving interface MAC*/
    if(IS_INTF_L3_MODE(interface) &&
        memcmp(IF_MAC(interface), 
        ethernet_hdr->dst_mac.mac, 
        sizeof(mac_add_t)) == 0){
        /*case 1*/
        return TRUE;
    }

    /*If interface is working in L3 mode, then accept the frame with
     * broadcast MAC*/
    if(IS_INTF_L3_MODE(interface) &&
        IS_MAC_BROADCAST_ADDR(ethernet_hdr->dst_mac.mac)){
        /*case 1*/
        return TRUE;
    }

    return FALSE;
}

ethernet_hdr_t *
untag_pkt_with_vlan_id(ethernet_hdr_t *ethernet_hdr,
                     unsigned int total_pkt_size,
                     unsigned int *new_pkt_size);

ethernet_hdr_t *
tag_pkt_with_vlan_id(ethernet_hdr_t *ethernet_hdr,
                     unsigned int total_pkt_size,
                     int vlan_id,
                     unsigned int *new_pkt_size);

// void
// interface_set_l2_mode(node_t *node, 
//                       interface_t *interface, 
//                       char *l2_mode_option);

// void
// interface_set_vlan(node_t *node,
//                    interface_t *interface,
//                    unsigned int vlan_id);

void
node_set_intf_vlan_membsership(node_t *node, char *intf_name, 
                                unsigned int vlan_id);

void
node_set_intf_l2_mode(node_t *node, char *intf_name, 
                        intf_l2_mode_t intf_l2_mode);

void
promote_pkt_to_layer2(node_t * node, interface_t *recv_interf,
                        ethernet_hdr_t *ethernet_hdr, u_int32_t pkt_size);

void
demote_pkt_to_layer2(node_t * node, u_int32_t next_hop_ip,
                    char *outgoing_intf,  char *pkt, u_int32_t pkt_size,
                    int protocol_number);
#endif /* __LAYER2__ */