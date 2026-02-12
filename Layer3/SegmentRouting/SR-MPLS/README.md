# SRGB - Segment Routing Global Block Library

## Overview

The SRGB (Segment Routing Global Block) library provides a complete implementation for managing MPLS label allocation in SR-MPLS networks. This library is designed to be used by routing protocols like ISIS and OSPF for Segment Routing operations.

## Key Concepts

### What is SRGB?

The SRGB is a contiguous block of MPLS labels reserved for segment routing:

```
SRGB Range: [Base Label ... Base Label + Range Size - 1]
Example:    [16000 ... 23999]  (Base=16000, Size=8000)

Label Calculation:
  MPLS Label = SRGB Base + SID Index
  
  Example: 
    If router advertises prefix with SID index 100
    Label = 16000 + 100 = 16100
```

### Why SRGB?

- **Consistency**: All routers in the SR domain use the same SRGB range
- **Predictability**: Labels are calculated using simple arithmetic
- **Scalability**: Supports large-scale SR deployments
- **Interoperability**: Works with ISIS, OSPF, and BGP

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   SR-MPLS Clients                       │
│         (ISIS, OSPF, BGP, Static Routes)                │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │   SRGB Library API    │
         ├───────────────────────┤
         │ • Label Allocation    │
         │ • Index Management    │
         │ • Client Registration │
         │ • Statistics          │
         └───────────┬───────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │   Bitmap + Tables     │
         │ (Allocation Tracking) │
         └───────────────────────┘
```

## Features

### Core Functionality
- ✅ Dynamic SRGB creation and configuration
- ✅ Label allocation by index (static assignment)
- ✅ Dynamic label allocation (first available)
- ✅ Multi-client support (ISIS, OSPF, BGP, Static)
- ✅ Index ↔ Label conversion utilities
- ✅ Label usage tracking and statistics
- ✅ Comprehensive error handling

### Advanced Features
- ✅ Client registration and management
- ✅ Per-client label tracking
- ✅ Reconfiguration support
- ✅ Reference counting
- ✅ Detailed statistics
- ✅ Debug and display functions

## API Reference

### Basic Usage Flow

```c
// 1. Create SRGB
srgb_t *srgb;
srgb_create(16000, 8000, "SR-MPLS-SRGB", &srgb);

// 2. Register client
srgb_register_client(srgb, SRGB_CLIENT_ISIS);

// 3. Allocate labels
uint32_t label;
srgb_alloc_label_by_index(srgb, 100, SRGB_CLIENT_ISIS, NULL, &label);
// label = 16100

// 4. Free labels when done
srgb_free_label(srgb, label, SRGB_CLIENT_ISIS);

// 5. Cleanup
srgb_destroy(srgb);
```

### Complete Example (ISIS Integration)

```c
#include "srgb.h"

void isis_sr_mpls_example(void)
{
    srgb_t *srgb = NULL;
    srgb_error_t rc;
    uint32_t label;
    uint32_t index;
    srgb_stats_t stats;
    
    // Create SRGB for ISIS
    rc = srgb_create(16000, 8000, "ISIS-SRGB", &srgb);
    if (rc != SRGB_OK) {
        printf("Failed to create SRGB: %s\n", srgb_error_to_string(rc));
        return;
    }
    
    // Register ISIS as a client
    rc = srgb_register_client(srgb, SRGB_CLIENT_ISIS);
    if (rc != SRGB_OK) {
        printf("Failed to register ISIS: %s\n", srgb_error_to_string(rc));
        srgb_destroy(srgb);
        return;
    }
    
    // Allocate prefix SID with index 100 for loopback
    rc = srgb_alloc_label_by_index(srgb, 100, SRGB_CLIENT_ISIS, 
                                    NULL, &label);
    if (rc == SRGB_OK) {
        printf("Allocated prefix SID: Label=%u, Index=%u\n", label, 100);
        // Advertise this in ISIS LSP with SID index 100
    }
    
    // Allocate dynamic adjacency SID
    rc = srgb_alloc_label_dynamic(srgb, SRGB_CLIENT_ISIS, 
                                  NULL, &label, &index);
    if (rc == SRGB_OK) {
        printf("Allocated adjacency SID: Label=%u, Index=%u\n", 
               label, index);
    }
    
    // Check if a label is in use
    if (srgb_is_label_allocated(srgb, 16100)) {
        printf("Label 16100 is allocated\n");
    }
    
    // Get statistics
    srgb_get_stats(srgb, &stats);
    printf("SRGB Stats: Allocated=%u, Free=%u\n",
           stats.allocated_labels, stats.free_labels);
    
    // Display SRGB configuration
    srgb_show(srgb, true);  // verbose=true
    
    // Free specific label
    srgb_free_label(srgb, label, SRGB_CLIENT_ISIS);
    
    // Unregister and cleanup
    srgb_unregister_client(srgb, SRGB_CLIENT_ISIS);
    srgb_destroy(srgb);
}
```

### Client Management

```c
// Register multiple clients
srgb_register_client(srgb, SRGB_CLIENT_ISIS);
srgb_register_client(srgb, SRGB_CLIENT_OSPF);

// Check registration
if (srgb_is_client_registered(srgb, SRGB_CLIENT_ISIS)) {
    printf("ISIS is registered\n");
}

// Show labels for specific client
srgb_show_client_labels(srgb, SRGB_CLIENT_ISIS);

// Free all labels for a client
srgb_free_all_labels_by_client(srgb, SRGB_CLIENT_ISIS);

// Unregister (automatically frees all labels)
srgb_unregister_client(srgb, SRGB_CLIENT_ISIS);
```

### Label Conversion

```c
// Convert index to label
uint32_t label;
srgb_index_to_label(srgb, 100, &label);
// label = 16100

// Convert label to index
uint32_t index;
srgb_label_to_index(srgb, 16100, &index);
// index = 100
```

### Configuration Management

```c
// Get current configuration
uint32_t base = srgb_get_base_label(srgb);      // 16000
uint32_t size = srgb_get_range_size(srgb);      // 8000
uint32_t end = srgb_get_end_label(srgb);        // 23999
const char *name = srgb_get_name(srgb);         // "ISIS-SRGB"

// Reconfigure SRGB (releases all allocations)
srgb_reconfigure(srgb, 20000, 10000);
// New range: [20000 - 29999]
```

## Integration with ISIS

### Prefix SID Allocation

```c
typedef struct isis_prefix_sid_ {
    uint32_t sid_index;
    uint32_t mpls_label;
    bool n_flag;  // Node-SID flag
    bool p_flag;  // Persistent flag
} isis_prefix_sid_t;

srgb_error_t 
isis_allocate_prefix_sid(srgb_t *srgb, 
                         uint32_t sid_index,
                         isis_prefix_sid_t *sid_out)
{
    srgb_error_t rc;
    uint32_t label;
    
    // Allocate label for this prefix SID index
    rc = srgb_alloc_label_by_index(srgb, sid_index, 
                                    SRGB_CLIENT_ISIS, 
                                    sid_out, &label);
    if (rc != SRGB_OK) {
        return rc;
    }
    
    sid_out->sid_index = sid_index;
    sid_out->mpls_label = label;
    sid_out->n_flag = true;   // Node-SID
    sid_out->p_flag = true;   // Persistent
    
    return SRGB_OK;
}
```

### Adjacency SID Allocation

```c
typedef struct isis_adj_sid_ {
    uint32_t mpls_label;
    uint32_t ifindex;
    uint8_t flags;
} isis_adj_sid_t;

srgb_error_t
isis_allocate_adj_sid(srgb_t *srgb,
                      uint32_t ifindex,
                      isis_adj_sid_t *adj_sid)
{
    srgb_error_t rc;
    uint32_t label, index;
    
    // Adjacency SIDs are typically allocated dynamically
    rc = srgb_alloc_label_dynamic(srgb, SRGB_CLIENT_ISIS,
                                  (void *)(uintptr_t)ifindex,
                                  &label, &index);
    if (rc != SRGB_OK) {
        return rc;
    }
    
    adj_sid->mpls_label = label;
    adj_sid->ifindex = ifindex;
    adj_sid->flags = 0;  // Set appropriate flags
    
    return SRGB_OK;
}
```

## Integration with OSPF

```c
typedef struct ospf_sr_config_ {
    srgb_t *srgb;
    uint32_t router_sid_index;
    uint32_t router_sid_label;
} ospf_sr_config_t;

int ospf_sr_init(ospf_sr_config_t *sr_cfg)
{
    srgb_error_t rc;
    
    // Create OSPF SRGB
    rc = srgb_create(16000, 8000, "OSPF-SRGB", &sr_cfg->srgb);
    if (rc != SRGB_OK) {
        return -1;
    }
    
    // Register OSPF client
    srgb_register_client(sr_cfg->srgb, SRGB_CLIENT_OSPF);
    
    // Allocate router SID (e.g., index 200)
    sr_cfg->router_sid_index = 200;
    rc = srgb_alloc_label_by_index(sr_cfg->srgb, 
                                    sr_cfg->router_sid_index,
                                    SRGB_CLIENT_OSPF,
                                    NULL,
                                    &sr_cfg->router_sid_label);
    if (rc != SRGB_OK) {
        srgb_destroy(sr_cfg->srgb);
        return -1;
    }
    
    return 0;
}
```

## Error Handling

All SRGB functions return error codes. Always check return values:

```c
srgb_error_t rc;
uint32_t label;

rc = srgb_alloc_label_by_index(srgb, 100, SRGB_CLIENT_ISIS, NULL, &label);

switch (rc) {
    case SRGB_OK:
        // Success - use the label
        break;
    case SRGB_ERR_INDEX_OUT_OF_RANGE:
        printf("Index 100 is out of SRGB range\n");
        break;
    case SRGB_ERR_LABEL_IN_USE:
        printf("Label already allocated\n");
        break;
    default:
        printf("Error: %s\n", srgb_error_to_string(rc));
        break;
}
```

## Best Practices

### 1. Use Consistent SRGB Across Domain
```c
// All routers should use the same SRGB range
#define SR_DOMAIN_SRGB_BASE  16000
#define SR_DOMAIN_SRGB_SIZE  8000

srgb_create(SR_DOMAIN_SRGB_BASE, SR_DOMAIN_SRGB_SIZE, name, &srgb);
```

### 2. Register Clients Before Allocation
```c
// Always register before allocating
srgb_register_client(srgb, SRGB_CLIENT_ISIS);
// Now safe to allocate
srgb_alloc_label_by_index(srgb, 100, SRGB_CLIENT_ISIS, NULL, &label);
```

### 3. Use Static Indices for Prefix SIDs
```c
// Prefix SIDs should use predictable indices
// E.g., Router ID last octet as index
uint32_t router_id = 0x0A0A0A64;  // 10.10.10.100
uint32_t sid_index = router_id & 0xFF;  // 100

srgb_alloc_label_by_index(srgb, sid_index, SRGB_CLIENT_ISIS, NULL, &label);
```

### 4. Use Dynamic Allocation for Adjacency SIDs
```c
// Adjacency SIDs can be allocated dynamically
srgb_alloc_label_dynamic(srgb, SRGB_CLIENT_ISIS, NULL, &label, &index);
```

### 5. Monitor Statistics
```c
srgb_stats_t stats;
srgb_get_stats(srgb, &stats);

if (stats.free_labels < 100) {
    printf("WARNING: SRGB nearly exhausted!\n");
    printf("  Free: %u, Allocated: %u\n", 
           stats.free_labels, stats.allocated_labels);
}
```

### 6. Clean Up Properly
```c
// Free labels before destroying
srgb_free_all_labels_by_client(srgb, SRGB_CLIENT_ISIS);

// Unregister clients
srgb_unregister_client(srgb, SRGB_CLIENT_ISIS);

// Destroy SRGB
srgb_destroy(srgb);
```

## Thread Safety

**Note**: The current implementation is **not thread-safe**. If using in a multi-threaded environment, you must provide external synchronization:

```c
pthread_mutex_t srgb_mutex = PTHREAD_MUTEX_INITIALIZER;

// Protect SRGB operations
pthread_mutex_lock(&srgb_mutex);
srgb_alloc_label_by_index(srgb, 100, SRGB_CLIENT_ISIS, NULL, &label);
pthread_mutex_unlock(&srgb_mutex);
```

## Performance Considerations

- **Label Allocation**: O(1) for index-based, O(n) for dynamic (bitmap scan)
- **Label Free**: O(1)
- **Lookup**: O(1)
- **Memory**: ~20 bytes per label in range

For a typical SRGB of 8000 labels: ~160 KB memory overhead

## Debugging

Enable verbose output:

```c
// Show detailed SRGB information
srgb_show(srgb, true);

// Show client-specific allocations
srgb_show_client_labels(srgb, SRGB_CLIENT_ISIS);

// Get label information
srgb_label_info_t info;
if (srgb_get_label_info(srgb, label, &info) == SRGB_OK) {
    printf("Label %u: Index=%u, Client=%s, RefCount=%u\n",
           info.label, info.index, 
           srgb_client_to_string(info.client),
           info.ref_count);
}
```

## Limitations

1. Maximum range size: 1,000,000 labels
2. Label range: 16 - 1,048,575
3. No automatic label compaction/defragmentation
4. Not thread-safe (requires external locking)

## Future Enhancements

- [ ] Thread-safe operations (mutex protection)
- [ ] Label reservation (pre-reserve ranges)
- [ ] Label allocation callbacks
- [ ] Persistent storage support
- [ ] Multi-SRGB support per router
- [ ] SRLB (Segment Routing Local Block) support

## References

- RFC 8660 - Segment Routing with MPLS Data Plane
- RFC 8402 - Segment Routing Architecture
- RFC 8667 - ISIS Extensions for Segment Routing
- RFC 8665 - OSPF Extensions for Segment Routing

## License

Part of TCP/IP Stack Project
