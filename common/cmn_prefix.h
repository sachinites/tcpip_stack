#ifndef __CMN_PREFIX__
#define __CMN_PREFIX__

#include <stdint.h>

typedef struct bitmap_ bitmap_t;

typedef enum RTM_AFI_ {

    AF_IPV4,
    AF_IPV6,
    AF_LABEL,
    AF_MAC,
    AFI_MAX

} AFI_T;

#pragma pack(push, 8)

typedef struct cmn_prefix_ {

    union {
        uint32_t v4_addr;
        uint16_t v6_addr[8];
        uint32_t mpls_label;
        uint8_t mac_addr[6];
    } u;

    uint8_t prefix_len;
    AFI_T afi;

} cmn_prefix_t;

#pragma pack(pop)

/* Helper function to convert AFI to string */

bool cmn_prefix_is_null (cmn_prefix_t *prefix);
void cmn_prefix_initialize_v4 (cmn_prefix_t *prefix, uint32_t ip_addr, uint8_t mask);
void cmn_prefix_initialize_v6 (cmn_prefix_t *prefix, uint8_t (*addr)[16], uint8_t mask);

/* Helper Functions for Prefix to Bitmap Conversion */
void cmn_prefix_to_bitmap(cmn_prefix_t *prefix, bitmap_t *bm);
void cmn_prefix_to_wildcard_bitmap(cmn_prefix_t *prefix, bitmap_t *wildcard);
int8_t
cmn_prefix_compare(const cmn_prefix_t *p1, const cmn_prefix_t *p2) ;
char *
cmn_prefix_to_string(cmn_prefix_t *prefix, char (*buffer)[48]);
bool 
cmn_parse_prefix_string(const char *prefix_str, cmn_prefix_t *prefix);

void 
cmn_prefix_to_bitmap(cmn_prefix_t *prefix, 
                     bitmap_t *bm_prefix, 
                     bitmap_t *bm_mask);


#endif /* __CMN_PREFIX__ */
