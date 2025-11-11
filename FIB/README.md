# FIB - Forwarding Information Base

Hardware-simulated forwarding engine using mtrie data structure.

## Quick Start

### Build the Library
```bash
cd FIB
make
```

This creates `libfib.a` static library.

### Clean Build
```bash
make clean
```

## Key Features

### 🔍 Intelligent Lookup Strategy
- **IPv4 & IPv6**: Longest Prefix Match (LPM)
  - Supports hierarchical routing with overlapping prefixes
  - Example: 10.0.0.0/8 and 10.1.0.0/16
  
- **MPLS Labels & MAC Addresses**: Exact Match
  - Flat address space requires exact match
  - No prefix hierarchy in label/MAC forwarding

### ⚡ Performance
- O(k) lookup time (k = stride length)
- Fast mtrie-based implementation
- Thread-safe ECMP load balancing (up to 8 nexthops)
- Per-route load balancing index (no global state)

### 🏷️ MPLS Support
- Push, Pop, Swap operations
- Label stack management
- Stack bottom bit handling

## API Reference

### Initialize FIB
```c
fib_t *fib_init(FIB_AFI_T afi);
```
- **afi**: `FIB_AF_IPV4`, `FIB_AF_IPV6`, `FIB_AF_LABEL`, `FIB_AFI_MAC`
- **Returns**: FIB pointer or NULL on failure

### Add Route
```c
fib_error_t fib_add_route(fib_t *fib, fib_prefix_t *prefix, fib_nh_t *nh);
```
- Adds route or nexthop to ECMP group
- **Returns**: 0 on success

### Delete Route
```c
fib_error_t fib_del_route(fib_t *fib, fib_prefix_t *prefix, fib_nh_t *nh);
```
- `nh = NULL`: Delete entire route
- `nh != NULL`: Delete specific nexthop
- **Returns**: 0 on success

### Forward Packet
```c
fib_error_t fib_forward(fib_t *fib, pkt_block_t *pkt);
```
- Extracts destination from packet
- Performs AFI-appropriate lookup (LPM or exact match)
- Applies label operations
- Decrements TTL
- **Returns**: `FIB_ERROR_SUCCESS` on success

### Display FIB
```c
void fib_show(fib_t *fib);
```
- Displays all routes in the FIB
- Shows nexthops and ECMP groups
- Displays label stacks for MPLS entries
- Shows lookup method (LPM vs Exact Match)

## Lookup Behavior by AFI

| AFI Type | Lookup Method | Use Case |
|----------|--------------|----------|
| `FIB_AF_IPV4` | LPM | IPv4 routing |
| `FIB_AF_IPV6` | LPM | IPv6 routing |
| `FIB_AF_LABEL` | Exact Match | MPLS label forwarding |
| `FIB_AFI_MAC` | Exact Match | MAC address switching |

### Why Different Lookup Methods?

**LPM (Longest Prefix Match)** for IP addresses:
- IP routing is hierarchical
- Routes can overlap (e.g., 0.0.0.0/0 default route)
- Need to find most specific match

**Exact Match** for MPLS/MAC:
- MPLS labels are flat identifiers (no hierarchy)
- MAC addresses are flat L2 identifiers
- Only exact label/MAC matches are valid
- No concept of "more specific" label

## Example Usage

### IPv4 FIB (LPM)
```c
// Create IPv4 FIB
fib_t *ipv4_fib = fib_init(FIB_AF_IPV4);

// Add default route (0.0.0.0/0)
fib_prefix_t prefix_default = {
    .afi = FIB_AF_IPV4,
    .u.v4_addr = 0x00000000,
    .prefix_len = 0
};

// Add specific route (10.0.0.0/8)
fib_prefix_t prefix_10 = {
    .afi = FIB_AF_IPV4,
    .u.v4_addr = 0x0A000000,
    .prefix_len = 8
};

// LPM lookup will find most specific match
// 10.1.2.3 -> matches 10.0.0.0/8 (more specific than 0.0.0.0/0)
```

### MPLS FIB (Exact Match)
```c
// Create MPLS FIB
fib_t *mpls_fib = fib_init(FIB_AF_LABEL);

// Add label entry
fib_prefix_t prefix_label = {
    .afi = FIB_AF_LABEL,
    .u.mpls_label = 100,
    .prefix_len = 20  // Full 20-bit label
};

// Exact match required
// Label 100 -> matches only label 100
// Label 101 -> no match (different label)
```

### MAC FIB (Exact Match)
```c
// Create MAC FIB
fib_t *mac_fib = fib_init(FIB_AFI_MAC);

// Add MAC entry
fib_prefix_t prefix_mac = {
    .afi = FIB_AFI_MAC,
    .u.mac_addr = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
    .prefix_len = 48  // Full 48-bit MAC
};

// Exact match required
// 00:11:22:33:44:55 -> matches
// 00:11:22:33:44:56 -> no match
```

## Error Codes

All FIB functions return `fib_error_t` error codes defined in `fib_error.h`:

| Constant | Value | Meaning |
|----------|-------|---------|
| `FIB_ERROR_SUCCESS` | 0 | Operation successful |
| `FIB_ERROR_INVALID_PARAM` | 1 | Invalid parameters passed |
| `FIB_ERROR_AFI_MISMATCH` | 2 | AFI mismatch between FIB and prefix |
| `FIB_ERROR_INSERT_FAILED` | 3 | Mtrie insert operation failed |
| `FIB_ERROR_ALLOC_FAILED` | 4 | Memory allocation failed |
| `FIB_ERROR_NO_ROUTE_DATA` | 5 | Route data missing in mtrie node |
| `FIB_ERROR_ECMP_LIMIT` | 6 | ECMP nexthop limit reached (max 8) |
| `FIB_ERROR_ROUTE_NOT_FOUND` | 7 | Route not found in FIB |
| `FIB_ERROR_NEXTHOP_NOT_FOUND` | 8 | Nexthop not found in route |
| `FIB_ERROR_EXTRACT_DEST_FAILED` | 9 | Cannot extract destination from packet |
| `FIB_ERROR_NO_ROUTE` | 10 | No matching route found (lookup) |
| `FIB_ERROR_NO_VALID_NEXTHOP` | 11 | No valid nexthop available |
| `FIB_ERROR_TTL_EXPIRED` | 12 | Packet TTL expired |
| `FIB_ERROR_UNKNOWN` | 13 | Unknown error |

### Error to String Conversion
```c
const char *fib_error_str(fib_error_t error);
```
Converts error code to human-readable string.

## Files

- **fib.cpp** - Core FIB implementation
- **fib_api.cpp** - Helper functions
- **fib.h** - Main FIB header
- **fib_api.h** - Helper function declarations
- **fib_common.h** - Common data structures
- **fib_enums.h** - AFI and operation enums
- **fib_nh.h** - Nexthop structure
- **fib_route.h** - Route structure
- **fib_error.h** - Error codes
- **Makefile** - Build configuration
- **libfib.a** - Static library (generated)

## Dependencies

- `../mtrie/` - Mtrie data structure
- `../BitOp/` - Bitmap operations
- `../LinuxMemoryManager/` - Memory management
- `../pkt_block.h` - Packet abstraction
- `../Interface/` - Interface management

## Integration

To use in your project:

1. Build the library: `cd FIB && make`
2. Link with your project: `-LFIB -lfib`
3. Include header: `#include "FIB/fib.h"`

Or integrate object files directly:
```makefile
OBJS += FIB/fib.o FIB/fib_api.o
```

## Architecture

```
┌─────────────────────────────────────┐
│        Application Layer            │
└────────────┬────────────────────────┘
             │
             │ fib_forward()
             ▼
┌─────────────────────────────────────┐
│          FIB Layer                  │
│  ┌─────────────────────────────┐   │
│  │ AFI-based Lookup Selector   │   │
│  └──┬───────────────────────┬──┘   │
│     │                       │       │
│     ▼                       ▼       │
│  ┌──────┐              ┌────────┐  │
│  │ LPM  │              │ Exact  │  │
│  │IPv4/6│              │MPLS/MAC│  │
│  └──────┘              └────────┘  │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│        Mtrie Data Structure         │
└─────────────────────────────────────┘
```

## Performance Tips

1. **Pre-allocate Routes**: Add routes before forwarding to avoid runtime allocation
2. **ECMP**: Use multiple nexthops for load distribution
3. **AFI Separation**: Use separate FIBs per address family
4. **Batch Operations**: Group route adds/deletes together

## License

Part of the tcpip_stack project. See main project LICENSE.

## Author

Implementation Date: November 11, 2025

