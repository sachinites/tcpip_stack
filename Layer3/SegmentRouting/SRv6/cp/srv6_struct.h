#ifndef __SRV6_STRUCT_H__
#define __SRV6_STRUCT_H__

#include "../common/srv6_const.h"
#include "../../../../libs/common/ipv6_hdrs.h"

/* Locator do not have flavors, end point fn is
    default to shift and forward in remote nodes and
    decapsulate on local node*/

#pragma pack(push, 8)
typedef struct srv6_locator_ {

    char name[LOCATOR_NAME_SIZE ];
    ipv6_addr_t sid;
    uint8_t prefix_len;
    uint8_t algo;
    avltree_t cfg_pfxsid_tree;
    avltree_t cfg_adjsid_tree;

} srv6_locator_t;

typedef struct srv6_pfxsid_ {

    ipv6_addr_t sid;
    Srv6_endpcode_t endP;
    uint8_t flags;
    uint8_t prefix_len;
    uint8_t n_seg_lst;
    ipv6_addr_t seglst[0];
    
} srv6_pfxsid_t;

typedef struct srv6_adjsid_ {

    ipv6_addr_t sid;
    ipv6_addr_t gw;
    Srv6_endpcode_t endP;
    uint32_t ifindex;
    uint8_t flags;
    uint8_t prefix_len;
    uint8_t n_seg_lst;
    ipv6_addr_t seglst[0];
    
} srv6_adjsid_t;

#pragma pack(pop)
#endif 
