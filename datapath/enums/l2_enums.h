/*
 * =============================================================================
 * File: l2_enums.h
 * Description: L2 (datapath) MAC origin flags and helpers.
 * =============================================================================
 *
 * Design:
 *   - These bits mark how a MacFwdObject was installed (STATIC / DP / EVPN-CP /
 *     VPLS-CP).  The same bits are OR'd onto mac_table_entry_t.flags while any
 *     oif of that class is present, and cleared when the last such oif is gone.
 *   - mac_entry_flag(): return string for CLI/logging of a single origin bit.
 * =============================================================================
 */

#ifndef __L2_ENUMS__
#define __L2_ENUMS__

#include <stdint.h>

/* Origin / install source — on MacFwdObject and aggregated on MAC entry */
#define MAC_STATIC           0x1
#define MAC_DATA_PLANE       0x2
#define EVPN_CONTROL_PLANE   0x4
#define VPLS_CONTROL_PLANE   0x8

#define MAC_ORIGIN_FLAGS \
    (MAC_STATIC | MAC_DATA_PLANE | EVPN_CONTROL_PLANE | VPLS_CONTROL_PLANE)

static inline const char *
mac_entry_flag (uint16_t mac_entry_flag) {

    switch(mac_entry_flag) {
        case MAC_STATIC : return "STATIC";
        case MAC_DATA_PLANE : return "DP";
        case EVPN_CONTROL_PLANE : return "EVPN-CP";
        case VPLS_CONTROL_PLANE : return "VPLS-CP";
        default: return "UNKNOWN";
    }
    return "nil";
}

#endif /* __L2_ENUMS__ */