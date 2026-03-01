#ifndef __GRESTRUCT__
#define __GRESTRUCT__

#include <stdint.h>
#include <stdbool.h>

typedef struct pkt_block_ pkt_block_t;
typedef struct dp_vrf_ dp_vrf_t;
typedef struct dp_intf_ dp_intf_t;
typedef struct dp_ctx_ dp_ctx_t;

#pragma pack (push,1)
typedef struct gre_header_ {

    // First 32 bits (4 bytes)
    uint16_t flags_version;   // 1st 2 bytes: Flags (C, R, K, S, s, Recur) and Version
    uint16_t protocol_type;   // 2nd 2 bytes: Protocol Type

    // Optional fields (only present if indicated by flags)
    uint16_t checksum;        // Checksum field (optional, 2 bytes)
    uint16_t reserved1;       // Reserved1 field (optional, 2 bytes)
    uint32_t key;             // Key field (optional, 4 bytes)
    uint32_t sequence_number; // Sequence Number field (optional, 4 bytes)
    uint32_t routing_info[];  // Routing Information (optional, variable length)

} gre_hdr_t;

#pragma pack(pop)

#endif 
