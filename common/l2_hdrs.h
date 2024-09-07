#ifndef __L2_PKT_HDRS__
#define __L2_PKT_HDRS__

#include <stdint.h>

#include "cmn_struct.h"

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

#pragma pack(pop)


#endif 