#ifndef __L2_PKT_HDRS__
#define __L2_PKT_HDRS__

#include <stdint.h>
#include <arpa/inet.h>
#include <cstddef>
#include "cmn_struct.h"
#include "protoIds.h"

#pragma pack (push,1)
typedef struct arp_hdr_{

    short hw_type;          /*1 for ethernet cable*/
    short proto_type;       /*0x0800 for IPV4*/
    unsigned char hw_addr_len;       /*6 for MAC*/
    unsigned char proto_addr_len;    /*4 for IPV4*/
    short op_code;          /*req or reply*/
    mac_addr_t src_mac;      /*MAC of OIF interface*/
    uint32_t src_ip;    /*IP of OIF*/
    mac_addr_t dst_mac;      /*?*/
    uint32_t dst_ip;        /*IP for which ARP is being resolved*/
} arp_hdr_t;

typedef struct vxlan_hdr_ {
    uint8_t flags;
    uint8_t reserved[3];
    uint8_t vni[3];
    uint8_t reserved2;
} vxlan_hdr_t;

typedef struct vlan_8021q_hdr_{

    unsigned short tpid; /* = 0x8100*/
    /* TCI stored in network byte order.
     * Layout on wire (MSB first): PCP[15:13] | DEI[12] | VID[11:0]
     * Use GET/SET macros below; never access tci directly. */
    unsigned short tci;

} vlan_8021q_hdr_t;

/* Extract PCP / DEI / VID from a network-byte-order TCI word */
#define TCI_PCP(tci_ne)   (( ntohs(tci_ne) >> 13) & 0x7)
#define TCI_DEI(tci_ne)   (( ntohs(tci_ne) >> 12) & 0x1)
#define TCI_VID(tci_ne)   (  ntohs(tci_ne)         & 0xFFF)

/* Build a network-byte-order TCI word from components */
#define MAKE_TCI(pcp, dei, vid) \
    htons((((pcp) & 0x7) << 13) | (((dei) & 0x1) << 12) | ((vid) & 0xFFF))

typedef struct vlan_ethernet_hdr_{

    mac_addr_t dst_mac;
    mac_addr_t src_mac;
    vlan_8021q_hdr_t vlan_8021q_hdr;
    unsigned short type;
    unsigned char payload[0];  /* Variable-length payload starts here */
  
} vlan_ethernet_hdr_t;

typedef struct ethernet_hdr_{

    mac_addr_t dst_mac;
    mac_addr_t src_mac;
    unsigned short type;
    unsigned char payload[0];  /* Variable-length payload starts here */

} ethernet_hdr_t;

#pragma pack(pop)


#define ETH_FCS_SIZE    (4)

#define ETH_HDR_SIZE_EXCL_PAYLOAD   (sizeof(ethernet_hdr_t))

#define ETH_FCS(eth_hdr_ptr, payload_size)  \
    (*(uint32_t *)(((char *)(((ethernet_hdr_t *)eth_hdr_ptr)->payload) + payload_size)))

static inline uint32_t
GET_802_1Q_VLAN_ID(vlan_8021q_hdr_t *vlan_8021q_hdr){

    return (uint32_t)TCI_VID(vlan_8021q_hdr->tci);
}

#define VLAN_ETH_FCS(vlan_eth_hdr_ptr, payload_size)  \
    (*(uint32_t *)(((char *)(((vlan_ethernet_hdr_t *)vlan_eth_hdr_ptr)->payload) + payload_size)))

#define VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD  (sizeof(vlan_ethernet_hdr_t))

/* Return 0 if not vlan tagged, else return pointer to 801.1q vlan hdr
 * present in ethernet hdr*/
static inline vlan_8021q_hdr_t *
is_pkt_vlan_tagged(ethernet_hdr_t *ethernet_hdr){

    /*Check the 13th and 14th byte of the ethernet hdr,
     *      * if is value is 0x8100 then it is vlan tagged*/

    vlan_8021q_hdr_t *vlan_8021q_hdr =
        (vlan_8021q_hdr_t *)((char *)ethernet_hdr + (sizeof(mac_addr_t) * 2));

    if(vlan_8021q_hdr->tpid == htons(ETH_TYPE_VLAN_8021Q))
        return vlan_8021q_hdr;

    return NULL;
}

/*fn to get access to ethernet payload address*/
static inline unsigned char *
GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr_t *ethernet_hdr){

   if(is_pkt_vlan_tagged(ethernet_hdr)){
        return ((vlan_ethernet_hdr_t *)(ethernet_hdr))->payload;
   }
   else
       return ethernet_hdr->payload;
}

#define GET_COMMON_ETH_FCS(eth_hdr_ptr, payload_size)   \
        (is_pkt_vlan_tagged(eth_hdr_ptr) ? VLAN_ETH_FCS(eth_hdr_ptr, payload_size) : \
            ETH_FCS(eth_hdr_ptr, payload_size))

static inline void
SET_COMMON_ETH_FCS(ethernet_hdr_t *ethernet_hdr, 
                   uint32_t payload_size,
                   uint32_t new_fcs){

    if(is_pkt_vlan_tagged(ethernet_hdr)){
        VLAN_ETH_FCS(ethernet_hdr, payload_size) = new_fcs;
    }
    else{
        ETH_FCS(ethernet_hdr, payload_size) = new_fcs;
    }
}

static inline void 
SET_COMMON_ETH_HDR_TYPE(ethernet_hdr_t *ethernet_hdr, uint16_t proto)
{
    if(is_pkt_vlan_tagged(ethernet_hdr)){
        vlan_ethernet_hdr_t *vlan_eth_hdr = (vlan_ethernet_hdr_t *)ethernet_hdr;
        vlan_eth_hdr->type = htons(proto);
    }
    else {
        ethernet_hdr->type = htons(proto);
    }
}

static inline uint32_t 
GET_ETH_HDR_SIZE_EXCL_PAYLOAD(ethernet_hdr_t *ethernet_hdr){

    if(is_pkt_vlan_tagged(ethernet_hdr)){
        return VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD;        
    }
    else{
        return ETH_HDR_SIZE_EXCL_PAYLOAD; 
    }
}

#endif 
