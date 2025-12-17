
#include <memory.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "cmn_prefix.h"
#include "../FIB/fib_api.h"
#include "../Layer3/ipv6/ipv6_utils.h"
#include "../BitOp/bitmap.h"
#include "../utils.h"

bool cmn_prefix_is_null (cmn_prefix_t *prefix) {

    /* For MPLS labels, check if label value is zero */
    if (prefix->afi == AF_LABEL) {
        return (prefix->u.mpls_label == 0);
    }
    
    /* For IP addresses, check if prefix_len is zero */
    if  (prefix->prefix_len == 0) return true;
    return false;
}

void 
cmn_prefix_initialize_v4(cmn_prefix_t *prefix, uint32_t ip_addr, uint8_t mask) {

    prefix->u.v4_addr = ip_addr;
    prefix->prefix_len = mask;
    prefix->afi = AF_IPV4;
}

void 
cmn_prefix_initialize_v6(cmn_prefix_t *prefix, uint8_t addr[16], uint8_t mask) {

    memcpy(prefix->u.v6_addr, addr, 16);
    prefix->prefix_len = mask;
    prefix->afi = AF_IPV6;
}

int8_t
cmn_prefix_compare(const cmn_prefix_t *p1, const cmn_prefix_t *p2) {
    
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
        case AF_IPV4:
            if (p1->u.v4_addr < p2->u.v4_addr) return -1;
            if (p1->u.v4_addr > p2->u.v4_addr) return 1;
            return 0;
            
        case AF_IPV6:
            return memcmp(p1->u.v6_addr, p2->u.v6_addr, 16);
            
        case AF_LABEL:
            if (p1->u.mpls_label < p2->u.mpls_label) return -1;
            if (p1->u.mpls_label > p2->u.mpls_label) return 1;
            return 0;
            
        case AF_MAC:
            return memcmp(p1->u.mac_addr, p2->u.mac_addr, 6);
            
        default:
            return 0;
    }
}

/* Helper function: Convert cmn_prefix_t to bitmap for mtrie operations */
void 
cmn_prefix_to_bitmap(cmn_prefix_t *prefix, bitmap_t *bm) {
    
    if (!prefix || !bm) return;
    
    switch (prefix->afi) {
        
        case AF_IPV4: {
            /* For IPv4, convert to network byte order and store in bitmap */
            uint32_t bin_ip = htonl(prefix->u.v4_addr);
            bm->bits[0] = bin_ip;
            bm->next += 32;
            break;
        }
        case AF_IPV6: {
            /* For IPv6, copy 16 bytes directly to bitmap */
            uint8_t *bm_array = (uint8_t *)(bm->bits + bm->next);
            for (int i = 0; i < 16; i++) {
                bm_array[i] = ((uint8_t *)prefix->u.v6_addr)[i];
            }
            bm->next += 128;
            break;
        }
        default:
            /* MPLS and MAC not supported for LPM */
            break;
    }
}

/* Helper function: Convert prefix length to wildcard bitmap (inverted mask) */
void 
cmn_prefix_to_wildcard_bitmap(cmn_prefix_t *prefix, bitmap_t *wildcard) {
    
    /* Set bits that are part of the prefix to 0 (care about these bits) */
    /* Set bits beyond the prefix length to 1 (don't care) */
    /* Create normal mask first, then invert it for wildcard */
    for (uint16_t i = 0; i < prefix->prefix_len; i++) {
        bitmap_set_bit_at(wildcard, i);
    }
    
    /* Invert to get wildcard (1 = don't care, 0 = care) */
    bitmap_inverse(wildcard, prefix->afi == AF_IPV4 ? 32 : 128);
}

/* Helper function to parse prefix string into cmn_prefix_t structure
 * Supports IPv4 (x.x.x.x/mask), IPv6 (x:x::x/mask), and MPLS labels
 * Returns true on success, false on failure
 */
bool cmn_parse_prefix_string(const char *prefix_str, cmn_prefix_t *prefix) {
    
    if (!prefix_str || !prefix) {
        return false;
    }
    
    memset(prefix, 0, sizeof(cmn_prefix_t));
    
    /* Check if this is an MPLS label (just a number) */
    char *slash_pos = strchr((char *)prefix_str, '/');
    char *colon_pos = strchr((char *)prefix_str, ':');
    
    /* If no slash and no colon in initial part, treat as MPLS label */
    if (!slash_pos && !colon_pos) {
        uint32_t label;
        if (sscanf(prefix_str, "%u", &label) == 1) {
            if (label > 1048575) {  /* MPLS labels are 20-bit */
                return false;
            }
            prefix->u.mpls_label = label;
            prefix->prefix_len = 0;
            prefix->afi = AF_LABEL;
            return true;
        }
        return false;
    }
    
    /* Check if this is IPv6 (contains colon before slash) */
    if (colon_pos && (!slash_pos || colon_pos < slash_pos)) {
        /* IPv6 address */
        char addr_str[48];
        uint8_t mask = 128;  /* Default mask */
        
        if (slash_pos) {
            /* Extract address and mask */
            size_t addr_len = slash_pos - prefix_str;
            if (addr_len >= sizeof(addr_str)) {
                return false;
            }
            strncpy(addr_str, prefix_str, addr_len);
            addr_str[addr_len] = '\0';
            
            if (sscanf(slash_pos + 1, "%hhu", &mask) != 1 || mask > 128) {
                return false;
            }
        } else {
            /* No mask specified, use full address */
            strncpy(addr_str, prefix_str, sizeof(addr_str) - 1);
            addr_str[sizeof(addr_str) - 1] = '\0';
        }
        
        /* Parse IPv6 address */
        ipv6_addr_t v6_addr;
        inet_pton6(addr_str, &v6_addr);
        
        memcpy(prefix->u.v6_addr, v6_addr.addr, 16);
        prefix->prefix_len = mask;
        prefix->afi = AF_IPV6;
        return true;
    }
    
    /* IPv4 address */
    char addr_str[20];
    uint8_t mask = 32;  /* Default mask */
    
    if (slash_pos) {
        /* Extract address and mask */
        size_t addr_len = slash_pos - prefix_str;
        if (addr_len >= sizeof(addr_str)) {
            return false;
        }
        strncpy(addr_str, prefix_str, addr_len);
        addr_str[addr_len] = '\0';
        
        if (sscanf(slash_pos + 1, "%hhu", &mask) != 1 || mask > 32) {
            return false;
        }
    } else {
        /* No mask specified, use full address */
        strncpy(addr_str, prefix_str, sizeof(addr_str) - 1);
        addr_str[sizeof(addr_str) - 1] = '\0';
    }
    
    /* Parse IPv4 address */
    uint32_t ip_addr = tcp_ip_convert_ip_p_to_n((c_string)addr_str);
    if (ip_addr == 0 && strcmp(addr_str, "0.0.0.0") != 0) {
        return false;
    }
    
    prefix->u.v4_addr = ip_addr;
    prefix->prefix_len = mask;
    prefix->afi = AF_IPV4;
    return true;
}

/* Convert FIB prefix to bitmap format for mtrie operations */
void 
cmn_prefix_to_bitmap(cmn_prefix_t *prefix, 
                     bitmap_t *bm_prefix, 
                     bitmap_t *bm_mask) {
    
    uint16_t stride_len = fib_get_stride_len_from_afi(prefix->afi);
    uint32_t mask_bits;
    
    bitmap_init(bm_prefix, stride_len);
    bitmap_init(bm_mask, stride_len);
    
    switch (prefix->afi) {
        case AF_IPV4:
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
            
        case AF_IPV6:
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
            
        case AF_LABEL:
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
            
        case AF_MAC:
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
