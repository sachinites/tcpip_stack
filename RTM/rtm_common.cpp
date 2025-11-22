#ifndef __RTM_COMMON__
#define __RTM_COMMON__

#include <memory.h>
#include "rtm_common.h"

bool rtm_prefix_is_null (rtm_prefix_t *prefix) {

    if  (prefix->prefix_len == 0) return true;
    return false;
}

void 
rtm_prefix_initialize_v4(rtm_prefix_t *prefix, uint32_t ip_addr, uint8_t mask) {

    prefix->u.v4_addr = ip_addr;
    prefix->prefix_len = mask;
    prefix->afi = RTM_AF_IPV4;
}

void 
rtm_prefix_initialize_v6(rtm_prefix_t *prefix, uint8_t addr[16], uint8_t mask) {

    memcpy(prefix->u.v6_addr, addr, 16);
    prefix->prefix_len = mask;
    prefix->afi = RTM_AF_IPV6;
}

int8_t
rtm_prefix_compare(const rtm_prefix_t *p1, const rtm_prefix_t *p2) {
    
    if (!p1 && p2) return 1;
    if (p1 && !p2) return -1;
    if (!p1 && !p2) return 0;

    // First compare AFI
    if (p1->afi != p2->afi) {
        return (p1->afi < p2->afi) ? -1 : 1;
    }
    
    // Then compare prefix length
    if (p1->prefix_len != p2->prefix_len) {
        return (p1->prefix_len < p2->prefix_len) ? -1 : 1;
    }
    
    // Finally compare the address based on AFI
    switch (p1->afi) {
        case RTM_AF_IPV4:
            if (p1->u.v4_addr < p2->u.v4_addr) return -1;
            if (p1->u.v4_addr > p2->u.v4_addr) return 1;
            return 0;
            
        case RTM_AF_IPV6:
            return memcmp(p1->u.v6_addr, p2->u.v6_addr, 16);
            
        case RTM_AF_LABEL:
            if (p1->u.mpls_label < p2->u.mpls_label) return -1;
            if (p1->u.mpls_label > p2->u.mpls_label) return 1;
            return 0;
            
        case RTM_AFI_MAC:
            return memcmp(p1->u.mac_addr, p2->u.mac_addr, 6);
            
        default:
            return 0;
    }
}

#endif 