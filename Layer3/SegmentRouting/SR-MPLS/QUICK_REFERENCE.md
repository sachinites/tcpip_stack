# SRGB Library - Quick Reference

## Quick Start (30 seconds)

```c
#include "srgb.h"

// Create SRGB
srgb_t *srgb;
srgb_create(16000, 8000, "My-SRGB", &srgb);

// Register client
srgb_register_client(srgb, SRGB_CLIENT_ISIS);

// Allocate label by index (for prefix SID)
uint32_t label;
srgb_alloc_label_by_index(srgb, 100, SRGB_CLIENT_ISIS, NULL, &label);
// Result: label = 16100

// Free label
srgb_free_label(srgb, label, SRGB_CLIENT_ISIS);

// Cleanup
srgb_destroy(srgb);
```

## Common Operations

### Create/Destroy
```c
srgb_t *srgb;
srgb_create(base, size, "name", &srgb);  // Create
srgb_reconfigure(srgb, new_base, new_size); // Reconfigure
srgb_destroy(srgb);                       // Destroy
```

### Client Management
```c
srgb_register_client(srgb, SRGB_CLIENT_ISIS);
srgb_is_client_registered(srgb, SRGB_CLIENT_ISIS);
srgb_unregister_client(srgb, SRGB_CLIENT_ISIS);
```

### Label Allocation
```c
// Static (by index)
srgb_alloc_label_by_index(srgb, index, client, data, &label);

// Dynamic (any available)
srgb_alloc_label_dynamic(srgb, client, data, &label, &index);

// Free
srgb_free_label(srgb, label, client);
srgb_free_label_by_index(srgb, index, client);
srgb_free_all_labels_by_client(srgb, client);
```

### Queries
```c
// Check
srgb_is_label_in_range(srgb, label);
srgb_is_index_valid(srgb, index);
srgb_is_label_allocated(srgb, label);

// Convert
srgb_index_to_label(srgb, index, &label);
srgb_label_to_index(srgb, label, &index);

// Info
srgb_label_info_t info;
srgb_get_label_info(srgb, label, &info);
```

### Configuration
```c
uint32_t base = srgb_get_base_label(srgb);
uint32_t size = srgb_get_range_size(srgb);
uint32_t end = srgb_get_end_label(srgb);
const char *name = srgb_get_name(srgb);
```

### Statistics
```c
srgb_stats_t stats;
srgb_get_stats(srgb, &stats);
srgb_reset_stats(srgb);
```

### Display
```c
srgb_show(srgb, false);              // Brief
srgb_show(srgb, true);               // Verbose
srgb_show_client_labels(srgb, client);
```

## Error Handling

```c
srgb_error_t rc = srgb_alloc_label_by_index(...);

if (rc != SRGB_OK) {
    printf("Error: %s\n", srgb_error_to_string(rc));
}
```

### Common Errors
- `SRGB_ERR_INVALID_PARAM` - Invalid parameter
- `SRGB_ERR_LABEL_IN_USE` - Label already allocated
- `SRGB_ERR_INDEX_OUT_OF_RANGE` - Index beyond SRGB range
- `SRGB_ERR_NO_LABELS_AVAILABLE` - SRGB exhausted

## Client Types

```c
SRGB_CLIENT_NONE    // No client
SRGB_CLIENT_ISIS    // ISIS protocol
SRGB_CLIENT_OSPF    // OSPF protocol
SRGB_CLIENT_BGP     // BGP protocol
SRGB_CLIENT_STATIC  // Static configuration
```

## Typical Workflows

### ISIS Prefix SID
```c
// Router with ID 10.10.10.1, use index 1
uint32_t index = 1;
uint32_t label;
srgb_alloc_label_by_index(srgb, index, SRGB_CLIENT_ISIS, NULL, &label);
// Advertise label 16001 with index 1 in ISIS LSP
```

### ISIS Adjacency SID
```c
// Dynamic allocation for adjacency
uint32_t label, index;
srgb_alloc_label_dynamic(srgb, SRGB_CLIENT_ISIS, adj_data, &label, &index);
// Use label for this adjacency
```

### OSPF Router SID
```c
// Similar to ISIS prefix SID
uint32_t router_sid_index = 200;
uint32_t label;
srgb_alloc_label_by_index(srgb, router_sid_index, 
                          SRGB_CLIENT_OSPF, NULL, &label);
// Advertise in OSPF Router Information LSA
```

## Label Calculation

```
Given:
  SRGB Base = 16000
  SRGB Size = 8000
  SRGB Range = [16000 - 23999]

Calculations:
  Label = Base + Index
  Index = Label - Base

Examples:
  Index 0   → Label 16000
  Index 100 → Label 16100
  Index 500 → Label 16500
  
  Label 16100 → Index 100
  Label 20000 → Index 4000
```

## Constants

```c
SRGB_MIN_LABEL_VALUE        16          // Minimum label
SRGB_MAX_LABEL_VALUE        1048575     // Maximum label
SRGB_DEFAULT_BASE_LABEL     16000       // Default base
SRGB_DEFAULT_RANGE_SIZE     8000        // Default size
SRGB_MAX_RANGE_SIZE         1000000     // Max range
SRGB_MAX_NAME_LEN           64          // Max name length
```

## Best Practices

1. **Always check return values**
   ```c
   if (srgb_alloc_label(...) != SRGB_OK) {
       // Handle error
   }
   ```

2. **Register before allocating**
   ```c
   srgb_register_client(srgb, client);
   srgb_alloc_label(...);
   ```

3. **Use static indices for prefix SIDs**
   ```c
   // Predictable, stable
   srgb_alloc_label_by_index(srgb, 100, ...);
   ```

4. **Use dynamic allocation for adjacency SIDs**
   ```c
   // Dynamic, temporary
   srgb_alloc_label_dynamic(srgb, ...);
   ```

5. **Clean up properly**
   ```c
   srgb_free_all_labels_by_client(srgb, client);
   srgb_unregister_client(srgb, client);
   srgb_destroy(srgb);
   ```

## Common Mistakes

❌ **Don't**: Allocate without registering
```c
srgb_alloc_label(srgb, 100, SRGB_CLIENT_ISIS, ...);  // May fail
```

✅ **Do**: Register first
```c
srgb_register_client(srgb, SRGB_CLIENT_ISIS);
srgb_alloc_label(srgb, 100, SRGB_CLIENT_ISIS, ...);
```

---

❌ **Don't**: Ignore return values
```c
srgb_alloc_label(...);  // What if it fails?
```

✅ **Do**: Check errors
```c
if (srgb_alloc_label(...) != SRGB_OK) {
    // Handle error
}
```

---

❌ **Don't**: Use same index twice
```c
srgb_alloc_label_by_index(srgb, 100, ISIS, ...);
srgb_alloc_label_by_index(srgb, 100, OSPF, ...);  // FAILS!
```

✅ **Do**: Use different indices
```c
srgb_alloc_label_by_index(srgb, 100, ISIS, ...);
srgb_alloc_label_by_index(srgb, 200, OSPF, ...);
```

## Debugging Tips

```c
// Enable verbose output
srgb_show(srgb, true);

// Check specific client
srgb_show_client_labels(srgb, SRGB_CLIENT_ISIS);

// Verify label info
srgb_label_info_t info;
if (srgb_get_label_info(srgb, label, &info) == SRGB_OK) {
    printf("Label %u: Index=%u, Client=%s\n",
           info.label, info.index, 
           srgb_client_to_string(info.client));
}

// Monitor usage
srgb_stats_t stats;
srgb_get_stats(srgb, &stats);
if (stats.free_labels < 100) {
    printf("WARNING: Low on labels!\n");
}
```

## Files

- `srgb.h` - Header file with API definitions
- `srgb.cpp` - Implementation
- `README.md` - Complete documentation
- `srgb_example.cpp` - Example code
- `QUICK_REFERENCE.md` - This file

## Build Integration

```makefile
# Add to Makefile
SRGB_OBJS = srgb.o

srgb.o: srgb.cpp srgb.h
	$(CC) $(CFLAGS) -c srgb.cpp

# Link with your protocol
isis: $(ISIS_OBJS) $(SRGB_OBJS)
	$(CC) $(ISIS_OBJS) $(SRGB_OBJS) -o isis
```

## Testing

```bash
# Compile example
g++ -o srgb_example srgb_example.cpp srgb.cpp \
    -I../../../BitOp -I../../../LinuxMemoryManager \
    -L../../../BitOp -lbitmap

# Run
./srgb_example
```

## Support

For issues or questions:
1. Check README.md for detailed documentation
2. Review srgb_example.cpp for usage patterns
3. Use srgb_show() for debugging

---
**Version**: 1.0  
**Created**: 2026-02-09  
**Part of**: TCP/IP Stack SR-MPLS Implementation
