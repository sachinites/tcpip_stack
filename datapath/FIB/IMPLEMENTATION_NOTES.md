# FIB Implementation Notes

## Overview
This implementation provides a high-performance Forwarding Information Base (FIB) using the mtrie (multibit trie) data structure. It simulates a hardware forwarding engine with support for multiple address families.

## Files Implemented

### 1. fib.cpp
Main FIB implementation with core functions:
- `fib_init()` - Initialize FIB with AFI-specific stride length
- `fib_add_route()` - Add routes with ECMP support
- `fib_del_route()` - Delete routes or specific nexthops
- `fib_forward()` - Perform LPM/exact lookup and packet forwarding
- `fib_show()` - Display FIB contents with all routes and nexthops

### 2. fib_api.h / fib_api.cpp
Helper functions for FIB operations:
- `fib_get_stride_len_from_afi()` - Map AFI to stride length
- `fib_prefix_to_bitmap()` - Convert FIB prefix to mtrie bitmap format
- `bitmap_to_fib_prefix()` - Convert bitmap back to FIB prefix
- `fib_extract_dest_from_pkt()` - Extract destination from packet headers
- `fib_forward_pkt_to_nh()` - Apply forwarding operations
- `fib_route_free_callback()` - Memory cleanup callback for mtrie

### 3. fib_error.h
Error code definitions:
- Complete set of error codes (SUCCESS through UNKNOWN)
- `fib_error_str()` - Convert error code to string
- Used consistently throughout all FIB code

### 4. Bug Fixes
- Fixed `fib_common.h` - Added missing union member to fix syntax error
- Fixed `fib_enums.h` - Corrected header guard typo (__FIN_ENUMS__ -> __FIB_ENUMS__)

## Address Family Support

### Stride Lengths by AFI:
- **FIB_AF_IPV4**: 32 bits (IPv4 addresses)
- **FIB_AF_IPV6**: 128 bits (IPv6 addresses)
- **FIB_AF_LABEL**: 20 bits (MPLS labels)
- **FIB_AFI_MAC**: 48 bits (MAC addresses)

## Key Features

### 1. Smart Lookup Strategy (AFI-based)
- **IPv4/IPv6**: Longest Prefix Match (LPM) for hierarchical routing
- **MPLS/MAC**: Exact Match lookup for flat address spaces
- Uses mtrie data structure for O(k) lookup where k is prefix length
- Efficient for hardware forwarding simulation

### 2. ECMP Support
- Up to 8 nexthops per route (FIB_MAX_ECMP_NH)
- Thread-safe round-robin load balancing across nexthops
- Per-route ECMP index (no static/global state)
- Automatic ECMP group management on route add/delete

### 3. MPLS Label Stack Operations
Supports standard MPLS operations:
- **PUSH**: Add label to stack (for label imposition)
- **POP**: Remove label from stack (for label disposition)
- **SWAP**: Replace label (for label swap/continue)

### 4. Packet Processing
- Header type detection (IP, IPv6, MPLS, Ethernet)
- TTL decrement for IP packets
- Stack bottom bit handling for MPLS
- Destination address extraction based on header type

## Implementation Details

### Route Storage
Routes are stored in mtrie with the following structure:
```
fib_route_t {
    fib_prefix_t *prefix;
    fib_nh_t *nh[FIB_MAX_ECMP_NH];
    uint8_t nh_index;  /* Per-route round-robin index for thread-safe ECMP */
}
```

**Thread Safety**: Each route maintains its own `nh_index` for ECMP load balancing, eliminating the need for static variables and ensuring thread-safe operation in multi-threaded environments.

### Bitmap Conversion
- Network byte order handling for multi-byte addresses
- Wildcard mask format: 1 = don't care, 0 = match
- IPv6 addresses converted from 8x16-bit to 4x32-bit representation

### Memory Management
- Uses XCALLOC2 from LinuxMemoryManager
- Proper cleanup via free callback registered with mtrie
- Field-by-field copy for structures with C++ objects (InterfaceP)

## Reference Implementation
Based on existing implementations:
- `layer3.c` - IP forwarding behavior
- `mpls_fwd.cpp` - MPLS label stack operations
- `mtrie.c` - mtrie data structure usage patterns

## Usage Example

```c
// Initialize FIB for IPv4
fib_t *fib = fib_init(FIB_AF_IPV4);

// Add a route
fib_prefix_t prefix;
prefix.afi = FIB_AF_IPV4;
prefix.u.v4_addr = 0x0A000000;  // 10.0.0.0
prefix.prefix_len = 8;

fib_nh_t nh;
nh.idx = 1;
nh.gateway.afi = FIB_AF_IPV4;
nh.gateway.u.v4_addr = 0x0A000001;  // 10.0.0.1
nh.oif = interface_ptr;
nh.lstack = NULL;

fib_add_route(fib, &prefix, &nh);

// Forward a packet
fib_forward(fib, pkt_block);

// Delete the route
fib_del_route(fib, &prefix, NULL);
```

## Error Codes
- 0: Success
- 1: Invalid parameters
- 2: AFI mismatch
- 3: Insert failed
- 4: Allocation failed
- 5: No route data
- 6: ECMP limit reached
- 7: Route not found
- 8: Nexthop not found
- 9: Cannot extract destination
- 10: No route found (lookup)
- 11: No valid nexthop

## Performance Characteristics

### Time Complexity:
- **Lookup**: O(k) where k is stride length / mtrie depth
- **Insert**: O(k) 
- **Delete**: O(k)

### Space Complexity:
- Depends on route count and prefix distribution
- Mtrie efficiently shares common prefixes
- Memory overhead for ECMP: O(n) per route where n ≤ 8

## Testing Recommendations

1. **Basic Operations**
   - Add/delete routes with various prefix lengths
   - Test ECMP with multiple nexthops
   - Verify LPM with overlapping prefixes (IPv4/IPv6)
   - Verify exact match for MPLS labels and MAC addresses

2. **MPLS Operations**
   - Test push/pop/swap operations
   - Verify stack bottom bit handling
   - Test multiple label stack depth

3. **Error Conditions**
   - Invalid parameters
   - AFI mismatches
   - ECMP limit exceeded
   - Memory allocation failures

4. **Performance**
   - Large route table sizes (10k, 100k, 1M routes)
   - Lookup speed benchmarks
   - Memory usage profiling

## Integration Notes

### Compilation

#### Building the Static Library
Use the provided Makefile to build `libfib.a`:
```bash
cd FIB
make clean
make
```

This creates:
- `libfib.a` - Static library (206KB)
- `fib.o` - FIB core implementation (with fib_show)
- `fib_api.o` - Helper functions (with display utilities)

#### Manual Compilation
Files can also be compiled individually:
```bash
g++ -c -g -Wall -Wextra -fpermissive -I.. fib.cpp -o fib.o
g++ -c -g -Wall -Wextra -fpermissive -I.. fib_api.cpp -o fib_api.o
ar rcs libfib.a fib.o fib_api.o
```

### Dependencies
- mtrie library (`../mtrie/`)
- BitOp library (`../BitOp/`)
- LinuxMemoryManager (`../LinuxMemoryManager/`)
- pkt_block interface (`../pkt_block.h`)
- Interface abstraction (`../Interface/`)

## Future Enhancements

1. **Statistics**
   - Per-route hit counters
   - Forwarding performance metrics
   - Memory usage statistics

2. **Advanced Features**
   - Policy-based routing
   - Route tagging/filtering
   - Priority-based nexthop selection

3. **Hardware Integration**
   - Actual hardware FIB programming
   - Sync between software and hardware FIB
   - Hardware counters integration

4. **IPv6 Full Support**
   - Complete IPv6 address handling
   - IPv6 extension headers
   - IPv6 ECMP

## Author
Implementation based on specifications and reference code from tcpip_stack project.
Date: November 11, 2025

