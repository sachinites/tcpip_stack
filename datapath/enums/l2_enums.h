/*
 * =============================================================================
 * File: l2_enums.h
 * Description: L2 (datapath) MAC entry flags and helpers.
 * =============================================================================
 *
 * Design:
 *   - MAC_STATIC, MAC_DATA_PLANE, MAC_CONTROL_PLANE: flags for MAC table entries.
 *   - mac_entry_flag(): return string for CLI/logging.
 * =============================================================================
 */

#ifndef __L2_ENUMS__
#define __L2_ENUMS__

#include <stdint.h>

/*L2 Switch Owns Mac Table*/
#define MAC_STATIC  0x1
#define MAC_DATA_PLANE 0x2
#define MAC_CONTROL_PLANE   0x4

static inline const char * 
mac_entry_flag (uint16_t mac_entry_flag) {

    switch(mac_entry_flag) {
        case MAC_STATIC : return "static";
        case MAC_DATA_PLANE : return "data-plane";
        case MAC_CONTROL_PLANE : return "control-plane";
        default: return "UNKNOWN";
    }
    return "nil";
}

#endif /* __L2_ENUMS__ */