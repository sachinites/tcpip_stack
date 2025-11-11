/*
 * =====================================================================================
 *
 *       Filename:  fib_api.cpp
 *
 *    Description:  Helper functions for FIB implementation
 *                  - Prefix format conversions (FIB prefix <-> bitmap)
 *                  - Packet destination extraction
 *                  - Nexthop forwarding operations
 *                  - MPLS label stack operations
 *
 * =====================================================================================
 */

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "fib_api.h"
#include "fib.h"
#include "fib_route.h"
#include "fib_nh.h"
#include "../pkt_block.h"
#include "../common/l3_hdrs.h"
#include "../tcpconst.h"
#include "../LinuxMemoryManager/uapi_mm.h"
#include "../Interface/Interface.h"

extern void
demote_pkt_to_layer2 (node_t *node,
                                       uint32_t next_hop_ip,
                                      c_string outgoing_intf,
                                      pkt_block_t *pkt_block,
                                      hdr_type_t hdr_type);

/**
 * Get stride length based on AFI
 * 
 * @param afi  Address Family Identifier
 * @return     Stride length in bits, 0 on error
 */
uint16_t fib_get_stride_len_from_afi(FIB_AFI_T afi) {
    switch (afi) {
        case FIB_AF_IPV4:
            return 32;  /* IPv4 address is 32 bits */
        case FIB_AF_IPV6:
            return 128; /* IPv6 address is 128 bits */
        case FIB_AF_LABEL:
            return 20;  /* MPLS label is 20 bits */
        case FIB_AFI_MAC:
            return 48;  /* MAC address is 48 bits */
        default:
            return 0;
    }
}

/* Convert FIB prefix to bitmap format for mtrie operations */
void fib_prefix_to_bitmap(fib_prefix_t *prefix, bitmap_t *bm_prefix, bitmap_t *bm_mask) {
    
    uint16_t stride_len = fib_get_stride_len_from_afi(prefix->afi);
    uint32_t mask_bits;
    
    bitmap_init(bm_prefix, stride_len);
    bitmap_init(bm_mask, stride_len);
    
    switch (prefix->afi) {
        case FIB_AF_IPV4:
            /* For IPv4, convert to network byte order */
            bm_prefix->bits[0] = htonl(prefix->u.v4_addr);
            
            /* Create mask: all 1s for prefix_len bits, then 0s */
            if (prefix->prefix_len == 0) {
                mask_bits = 0;
            } else if (prefix->prefix_len >= 32) {
                mask_bits = 0xFFFFFFFF;
            } else {
                mask_bits = 0xFFFFFFFF << (32 - prefix->prefix_len);
            }
            /* Wildcard mask: 1 means don't care, 0 means care */
            bm_mask->bits[0] = htonl(~mask_bits);
            break;
            
        case FIB_AF_IPV6:
            /* For IPv6, convert 8 uint16_t to bitmap */
            for (int i = 0; i < 8; i++) {
                uint16_t val = htons(prefix->u.v6_addr[i]);
                if (i % 2 == 0) {
                    bm_prefix->bits[i / 2] = (uint32_t)val << 16;
                } else {
                    bm_prefix->bits[i / 2] |= val;
                }
            }
            
            /* Create wildcard mask for IPv6 */
            for (int i = 0; i < 4; i++) {
                if (prefix->prefix_len <= i * 32) {
                    bm_mask->bits[i] = 0xFFFFFFFF;
                } else if (prefix->prefix_len >= (i + 1) * 32) {
                    bm_mask->bits[i] = 0;
                } else {
                    uint8_t bits_in_word = prefix->prefix_len - (i * 32);
                    mask_bits = 0xFFFFFFFF << (32 - bits_in_word);
                    bm_mask->bits[i] = htonl(~mask_bits);
                }
            }
            break;
            
        case FIB_AF_LABEL:
            /* For MPLS label, only use 20 bits */
            bm_prefix->bits[0] = (prefix->u.mpls_label & 0xFFFFF) << 12;
            
            if (prefix->prefix_len == 0) {
                mask_bits = 0;
            } else if (prefix->prefix_len >= 20) {
                mask_bits = 0xFFFFF << 12;
            } else {
                mask_bits = (0xFFFFF << (20 - prefix->prefix_len)) << 12;
            }
            bm_mask->bits[0] = ~mask_bits;
            break;
            
        case FIB_AFI_MAC:
            /* For MAC address, convert 6 bytes to bitmap */
            bm_prefix->bits[0] = ((uint32_t)prefix->u.mac_addr[0] << 24) |
                                 ((uint32_t)prefix->u.mac_addr[1] << 16) |
                                 ((uint32_t)prefix->u.mac_addr[2] << 8) |
                                 ((uint32_t)prefix->u.mac_addr[3]);
            bm_prefix->bits[1] = ((uint32_t)prefix->u.mac_addr[4] << 24) |
                                 ((uint32_t)prefix->u.mac_addr[5] << 16);
            
            /* Create wildcard mask for MAC */
            if (prefix->prefix_len >= 32) {
                bm_mask->bits[0] = 0;
                uint8_t remaining = prefix->prefix_len - 32;
                if (remaining >= 16) {
                    bm_mask->bits[1] = 0;
                } else if (remaining > 0) {
                    mask_bits = 0xFFFF << (16 - remaining);
                    bm_mask->bits[1] = ~(mask_bits << 16);
                } else {
                    bm_mask->bits[1] = 0xFFFFFFFF;
                }
            } else {
                if (prefix->prefix_len > 0) {
                    mask_bits = 0xFFFFFFFF << (32 - prefix->prefix_len);
                    bm_mask->bits[0] = ~mask_bits;
                } else {
                    bm_mask->bits[0] = 0xFFFFFFFF;
                }
                bm_mask->bits[1] = 0xFFFFFFFF;
            }
            break;
            
        default:
            break;
    }
}

/* Convert bitmap back to FIB prefix format */
void bitmap_to_fib_prefix(bitmap_t *bm_prefix, bitmap_t *bm_mask, uint16_t prefix_len, fib_prefix_t *prefix) {
    
    (void)bm_mask;  /* Unused parameter */
    
    /* Determine AFI based on prefix_len */
    if (prefix_len <= 32) {
        prefix->afi = FIB_AF_IPV4;
        prefix->prefix_len = prefix_len;
        prefix->u.v4_addr = ntohl(bm_prefix->bits[0]);
    } else if (prefix_len <= 128) {
        prefix->afi = FIB_AF_IPV6;
        prefix->prefix_len = prefix_len;
        for (int i = 0; i < 8; i++) {
            if (i % 2 == 0) {
                prefix->u.v6_addr[i] = ntohs((bm_prefix->bits[i / 2] >> 16) & 0xFFFF);
            } else {
                prefix->u.v6_addr[i] = ntohs(bm_prefix->bits[i / 2] & 0xFFFF);
            }
        }
    }
}

/* Extract destination address from packet based on header type */
bool fib_extract_dest_from_pkt(pkt_block_t *pkt, fib_prefix_t *dest) {
    
    hdr_type_t hdr_type = pkt_block_get_starting_hdr(pkt);
    pkt_size_t pkt_size;
    
    switch (hdr_type) {
        case IP_HDR:
        case IP_IN_IP_HDR: {
            ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr(pkt);
            if (!ip_hdr) return false;
            
            dest->afi = FIB_AF_IPV4;
            dest->prefix_len = 32;
            dest->u.v4_addr = ntohl(ip_hdr->dst_ip);
            return true;
        }
        
        case IP6_HDR: {
            /* IPv6 support would go here */
            return false;
        }
        
        case MPLS_HDR: {
            /* Extract MPLS label from packet */
            uint32_t *label_ptr = (uint32_t *)pkt_block_get_pkt(pkt, &pkt_size);
            if (!label_ptr || pkt_size < 4) return false;
            
            dest->afi = FIB_AF_LABEL;
            dest->prefix_len = 20;
            /* Extract 20-bit label from 32-bit label entry */
            dest->u.mpls_label = (ntohl(*label_ptr) >> 12) & 0xFFFFF;
            return true;
        }
        
        case ETH_HDR: {
            /* MAC destination would be extracted here */
            return false;
        }
        
        default:
            return false;
    }
}



/* Label format : 
    - ISt 20 bits label value 
    - TTL (3 bits)
    - Bottom of Stack (1 bit)
    - (Rest of 3 bits are reserved)
*/

/* Extract 20-bit label value from label_t */
typedef uint32_t label_val_t;

static inline uint32_t
get_label_value(label_val_t label) {
    return (label >> 12) & 0xFFFFF;
}

static void 
set_label_value (label_val_t *label, uint32_t value) {

    *label = 0;
    value &= 0xFFFFF;
    *label |= (value << 12);
}

/* Check if S (Bottom of Stack) bit is set */
static inline bool
is_stack_bottom(label_val_t label) {
    return (label >> 8) & 0x1;
}

/* Set S (Bottom of Stack) bit */
static inline void
set_stack_bottom(label_val_t *label) {
    *label |= (1 << 8);
}

/* Clear S (Bottom of Stack) bit */
static inline void 
clear_stack_bottom(label_val_t *label) {
    *label &= ~(1 << 8);
}

static bool 
label_stack_compare (fib_lstack_t *label_stk1, fib_lstack_t *label_stk2) {

    if (!label_stk1 && !label_stk2) return true;
    if (!label_stk1 && label_stk2) return false;
    if (label_stk1 && !label_stk2) return false;
    return ( memcmp (label_stk1, label_stk2, sizeof ( fib_lstack_t )) == 0 );
}


static void 
mpls_apply_label_stack_on_pkt (pkt_block_t *pkt_block, fib_lstack_t *lstack) {

    int i = 0;
    bool s_bit = false;
    pkt_size_t pkt_size;
    label_val_t *pkt_label;

    for (i = 0; i < FIB_MAX_LBL_DEPTH; i++) {

        if (lstack->labels[i].op == FIB_LBL_STACK_OPS_UNKNOWN) continue;

        switch (lstack->labels[i].op ) {

            case FIB_LBL_POP:
                if (pkt_block_get_starting_hdr (pkt_block) == MPLS_HDR) {
                    pkt_label = (label_val_t *)pkt_block_get_pkt (pkt_block, &pkt_size);
                    if (is_stack_bottom (*pkt_label)) s_bit = true;
                    pkt_block_set_new_pkt (pkt_block, (uint8_t *)(pkt_label + 1), pkt_size - sizeof (fib_label_t));
                    if (s_bit) pkt_block_set_starting_hdr_type (pkt_block,  MISC_APP_HDR);
                }
            break;


            case FIB_LBL_PUSH:
                pkt_block_expand_buffer_left (pkt_block, sizeof (fib_label_t));
                pkt_label = (label_val_t *)pkt_block_get_pkt (pkt_block, &pkt_size);
                set_label_value (pkt_label, get_label_value (lstack->labels[i].label_val ));
                if (pkt_block_get_starting_hdr (pkt_block) != MPLS_HDR) {
                    pkt_block_set_starting_hdr_type (pkt_block, MPLS_HDR);
                    set_stack_bottom (pkt_label);
                }
            break;


            case FIB_LBL_SWAP:
                s_bit = false;
                if (pkt_block_get_starting_hdr (pkt_block) == MPLS_HDR) {
                    pkt_label = (label_val_t *)pkt_block_get_pkt (pkt_block, &pkt_size);
                    if (is_stack_bottom (*pkt_label)) s_bit = true;
                    set_label_value (pkt_label, get_label_value (lstack->labels[i].label_val ));
                    if (s_bit) set_stack_bottom (pkt_label);
                }
            break;

        }
    }
};

/* Perform actual forwarding based on next hop */
fib_error_t fib_forward_pkt_to_nh(fib_t *fib, pkt_block_t *pkt_block, fib_nh_t *nh) {
    
    (void)fib;  /* Unused parameter - may be used for stats/debugging in future */
    
    if (!nh || !nh->oif) {
        return FIB_ERROR_NO_VALID_NEXTHOP;
    }
    
    /* Apply MPLS label stack operations if present */
    if (nh->lstack) {
        mpls_apply_label_stack_on_pkt  (pkt_block, nh->lstack);
    }
    
    /* For hardware FIB simulation, we just mark the packet as forwarded */
    /* In actual implementation, this would interface with hardware forwarding engine */
    
    /* Decrement TTL if IP packet */
    hdr_type_t hdr_type = pkt_block_get_starting_hdr(pkt_block);
    if (hdr_type == IP_HDR || hdr_type == IP_IN_IP_HDR) {
        ip_hdr_t *ip_hdr = pkt_block_get_ip_hdr(pkt_block);
        if (ip_hdr) {
            if (ip_hdr->ttl > 0) {
                ip_hdr->ttl--;
                if (ip_hdr->ttl == 0) {
                    /* TTL expired - drop packet */
                    return FIB_ERROR_TTL_EXPIRED;
                }
            }
        }
    }

    nh->hit_count++;

    #if 0
    demote_pkt_to_layer2(
        node,
        hdr_type == IP6_HDR ? 0 : nh->gateway.u.v4_addr ,
        (c_string)nh->oif->if_name.c_str(),
        pkt_block,
        IP6_HDR);
    #endif 

    /* Packet successfully processed - would be sent out OIF in real hardware */
    return FIB_ERROR_SUCCESS;
}

/* Free route data callback for mtrie */
void fib_route_free_callback(mtrie_node_t *node) {
    
    if (node->data) {
        fib_route_t *route = (fib_route_t *)node->data;
        
        /* Free the prefix */
        if (route->prefix) {
            XFREE(route->prefix);
        }
        
        /* Free next hops */
        for (int i = 0; i < FIB_MAX_ECMP_NH; i++) {
            if (route->nh[i]) {
                /* Free label stack if present */
                if (route->nh[i]->lstack) {
                    XFREE(route->nh[i]->lstack);
                }
                XFREE(route->nh[i]);
            }
        }
        
        /* Free the route itself */
        XFREE(route);
        node->data = NULL;
    }
}

/* Get AFI name as string */
const char *fib_afi_to_str(FIB_AFI_T afi) {
    switch (afi) {
        case FIB_AF_IPV4:
            return "IPv4";
        case FIB_AF_IPV6:
            return "IPv6";
        case FIB_AF_LABEL:
            return "MPLS";
        case FIB_AFI_MAC:
            return "MAC";
        default:
            return "Unknown";
    }
}

/* Get MPLS operation name as string */
const char *fib_mpls_op_to_str(fib_mpls_op_t op) {
    switch (op) {
        case FIB_LBL_PUSH:
            return "push";
        case FIB_LBL_POP:
            return "pop";
        case FIB_LBL_SWAP:
            return "swap";
        default:
            return "unknown";
    }
}

/* Convert prefix to string for display */
void fib_prefix_to_str(fib_prefix_t *prefix, char *buffer, int buf_size) {
    
    if (!prefix || !buffer || buf_size < 64) {
        if (buffer && buf_size > 0) buffer[0] = '\0';
        return;
    }
    
    switch (prefix->afi) {
        case FIB_AF_IPV4: {
            /* Convert IPv4 address to dotted decimal notation */
            uint32_t addr = prefix->u.v4_addr;
            snprintf(buffer, buf_size, "%d.%d.%d.%d/%d",
                    (addr >> 24) & 0xFF,
                    (addr >> 16) & 0xFF,
                    (addr >> 8) & 0xFF,
                    addr & 0xFF,
                    prefix->prefix_len);
            break;
        }
        
        case FIB_AF_IPV6: {
            /* Convert IPv6 address to colon-separated notation */
            snprintf(buffer, buf_size, 
                    "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x/%d",
                    prefix->u.v6_addr[0], prefix->u.v6_addr[1],
                    prefix->u.v6_addr[2], prefix->u.v6_addr[3],
                    prefix->u.v6_addr[4], prefix->u.v6_addr[5],
                    prefix->u.v6_addr[6], prefix->u.v6_addr[7],
                    prefix->prefix_len);
            break;
        }
        
        case FIB_AF_LABEL: {
            /* Display MPLS label as decimal number */
            snprintf(buffer, buf_size, "Label %u", prefix->u.mpls_label);
            break;
        }
        
        case FIB_AFI_MAC: {
            /* Display MAC address in standard format */
            snprintf(buffer, buf_size, "%02x:%02x:%02x:%02x:%02x:%02x",
                    prefix->u.mac_addr[0], prefix->u.mac_addr[1],
                    prefix->u.mac_addr[2], prefix->u.mac_addr[3],
                    prefix->u.mac_addr[4], prefix->u.mac_addr[5]);
            break;
        }
        
        default:
            snprintf(buffer, buf_size, "Unknown AFI");
            break;
    }
}

