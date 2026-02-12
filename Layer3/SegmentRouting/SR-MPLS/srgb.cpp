/*
 * =====================================================================================
 *
 *       Filename:  srgb.cpp
 *
 *    Description:  SRGB (Segment Routing Global Block) Implementation for SR-MPLS
 *
 *        Version:  1.0
 *        Created:  2026-02-09
 *       Compiler:  gcc/g++
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "srgb.h"
#include "../../../BitOp/bitmap.h"
#include "../../../BitOp/bitsop.h"
#include "../../../LinuxMemoryManager/uapi_mm.h"

/* External printf function used in the codebase */
extern int cprintf(const char *format, ...);

/* ========================================================================
 * Internal Structures
 * ======================================================================== */

/**
 * @brief Label entry in the allocation table
 */
typedef struct srgb_label_entry_ {
    bool allocated;           /* Is this label allocated? */
    srgb_client_t client;     /* Client that owns this label */
    uint32_t ref_count;       /* Reference count */
    void *user_data;          /* Client-specific data */
} srgb_label_entry_t;

/**
 * @brief SRGB internal structure
 */
struct srgb_ {
    char name[SRGB_MAX_NAME_LEN];      /* SRGB instance name */
    uint32_t base_label;                /* Starting label of the range */
    uint32_t range_size;                /* Number of labels in the range */
    uint32_t range_size_aligned;        /* Aligned to 32-bit boundary for bitmap */
    uint32_t end_label;                 /* Last label (base + size - 1) */
    
    /* Label allocation tracking */
    bitmap_t label_bitmap;              /* Bitmap for label allocation */
    srgb_label_entry_t *label_table;    /* Per-label allocation info */
    
    /* Client registration */
    uint32_t registered_clients;        /* Bitmask of registered clients */
    
    /* Statistics */
    srgb_stats_t stats;
};

/* ========================================================================
 * Internal Helper Functions
 * ======================================================================== */

/**
 * @brief Get label table index from label
 */
static inline uint32_t
srgb_label_to_table_index(srgb_t *srgb, uint32_t label)
{
    if (!srgb || label < srgb->base_label) {
        return 0;
    }
    return label - srgb->base_label;
}

/**
 * @brief Get label from table index
 */
static inline uint32_t
srgb_table_index_to_label(srgb_t *srgb, uint32_t index)
{
    if (!srgb) {
        return 0;
    }
    return srgb->base_label + index;
}

/**
 * @brief Count set bits in bitmap manually
 */
static uint32_t
srgb_count_allocated_labels(bitmap_t *bitmap, uint32_t max_index)
{
    uint32_t count = 0;
    uint32_t i;
    
    for (i = 0; i < max_index; i++) {
        if (bitmap_at(bitmap, i)) {
            count++;
        }
    }
    
    return count;
}

/**
 * @brief Update statistics
 */
static void
srgb_update_stats(srgb_t *srgb)
{
    if (!srgb) {
        return;
    }
    
    srgb->stats.allocated_labels = srgb_count_allocated_labels(&srgb->label_bitmap, 
                                                                srgb->range_size);
    srgb->stats.free_labels = srgb->stats.total_labels - srgb->stats.allocated_labels;
}

/* ========================================================================
 * SRGB Lifecycle Management
 * ======================================================================== */

srgb_error_t
srgb_create(uint32_t base_label, 
            uint32_t range_size,
            const char *name,
            srgb_t **srgb_out)
{
    srgb_t *srgb = NULL;
    srgb_error_t rc;
    uint32_t aligned_size;
    
    /* Validate parameters */
    if (!srgb_out) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    rc = srgb_validate_range(base_label, range_size);
    if (rc != SRGB_OK) {
        return rc;
    }
    
    /* Align range size to 32-bit boundary (bitmap requirement) */
    aligned_size = ((range_size + 31) / 32) * 32;
    
    /* Allocate SRGB structure */
    srgb = (srgb_t *)XCALLOC(0, 1, srgb_t);
    if (!srgb) {
        return SRGB_ERR_MEMORY_ALLOCATION;
    }
    
    /* Initialize basic fields */
    srgb->base_label = base_label;
    srgb->range_size = range_size;
    srgb->range_size_aligned = aligned_size;
    srgb->end_label = base_label + range_size - 1;
    srgb->registered_clients = 0;
    
    if (name) {
        strncpy(srgb->name, name, SRGB_MAX_NAME_LEN - 1);
        srgb->name[SRGB_MAX_NAME_LEN - 1] = '\0';
    } else {
        snprintf(srgb->name, SRGB_MAX_NAME_LEN, "SRGB_%u_%u", 
                 base_label, base_label + range_size - 1);
    }
    
    /* Initialize bitmap for label allocation tracking */
    bitmap_init(&srgb->label_bitmap, aligned_size);
    
    /* Allocate label table */
    srgb->label_table = (srgb_label_entry_t *)XCALLOC(0, range_size, srgb_label_entry_t);
    if (!srgb->label_table) {
        bitmap_free_internal(&srgb->label_bitmap);
        XFREE(srgb);
        return SRGB_ERR_MEMORY_ALLOCATION;
    }
    
    /* Initialize statistics */
    memset(&srgb->stats, 0, sizeof(srgb_stats_t));
    srgb->stats.total_labels = range_size;
    srgb->stats.free_labels = range_size;
    
    *srgb_out = srgb;
    return SRGB_OK;
}

srgb_error_t
srgb_destroy(srgb_t *srgb)
{
    if (!srgb) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    /* Free bitmap internal memory */
    bitmap_free_internal(&srgb->label_bitmap);
    
    /* Free label table */
    if (srgb->label_table) {
        XFREE(srgb->label_table);
    }
    
    /* Free SRGB structure */
    XFREE(srgb);
    
    return SRGB_OK;
}

srgb_error_t
srgb_reconfigure(srgb_t *srgb, uint32_t base_label, uint32_t range_size)
{
    srgb_label_entry_t *new_table = NULL;
    srgb_error_t rc;
    uint32_t aligned_size;
    
    if (!srgb) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    /* Validate new range */
    rc = srgb_validate_range(base_label, range_size);
    if (rc != SRGB_OK) {
        return rc;
    }
    
    /* Align range size to 32-bit boundary */
    aligned_size = ((range_size + 31) / 32) * 32;
    
    /* Create new label table */
    new_table = (srgb_label_entry_t *)XCALLOC(0, range_size, srgb_label_entry_t);
    if (!new_table) {
        return SRGB_ERR_MEMORY_ALLOCATION;
    }
    
    /* Free old bitmap memory */
    bitmap_free_internal(&srgb->label_bitmap);
    
    /* Free old label table */
    if (srgb->label_table) {
        XFREE(srgb->label_table);
    }
    
    /* Update SRGB */
    srgb->base_label = base_label;
    srgb->range_size = range_size;
    srgb->range_size_aligned = aligned_size;
    srgb->end_label = base_label + range_size - 1;
    srgb->label_table = new_table;
    
    /* Reinitialize bitmap */
    bitmap_init(&srgb->label_bitmap, aligned_size);
    
    /* Reset statistics */
    memset(&srgb->stats, 0, sizeof(srgb_stats_t));
    srgb->stats.total_labels = range_size;
    srgb->stats.free_labels = range_size;
    
    return SRGB_OK;
}

/* ========================================================================
 * Client Registration
 * ======================================================================== */

srgb_error_t
srgb_register_client(srgb_t *srgb, srgb_client_t client)
{
    if (!srgb) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    if (client >= SRGB_CLIENT_MAX) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    srgb->registered_clients |= client;
    return SRGB_OK;
}

srgb_error_t
srgb_unregister_client(srgb_t *srgb, srgb_client_t client)
{
    if (!srgb) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    if (client >= SRGB_CLIENT_MAX) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    /* Free all labels owned by this client */
    srgb_free_all_labels_by_client(srgb, client);
    
    /* Unregister client */
    srgb->registered_clients &= ~client;
    
    return SRGB_OK;
}

bool
srgb_is_client_registered(srgb_t *srgb, srgb_client_t client)
{
    if (!srgb || client >= SRGB_CLIENT_MAX) {
        return false;
    }
    
    return (srgb->registered_clients & client) != 0;
}

/* ========================================================================
 * Label Allocation and Management
 * ======================================================================== */

srgb_error_t
srgb_alloc_label_by_index(srgb_t *srgb,
                          uint32_t index,
                          srgb_client_t client,
                          void *user_data,
                          uint32_t *label_out)
{
    srgb_label_entry_t *entry;
    uint32_t label;
    
    /* Validate parameters */
    if (!srgb || !label_out) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    if (!srgb_is_index_valid(srgb, index)) {
        srgb->stats.alloc_failures++;
        return SRGB_ERR_INDEX_OUT_OF_RANGE;
    }
    
    /* Check if label is already allocated */
    if (bitmap_at(&srgb->label_bitmap, index)) {
        srgb->stats.alloc_failures++;
        return SRGB_ERR_LABEL_IN_USE;
    }
    
    /* Allocate the label */
    bitmap_set_bit_at(&srgb->label_bitmap, index);
    
    /* Update label table */
    entry = &srgb->label_table[index];
    entry->allocated = true;
    entry->client = client;
    entry->ref_count = 1;
    entry->user_data = user_data;
    
    /* Calculate label */
    label = srgb_table_index_to_label(srgb, index);
    *label_out = label;
    
    /* Update statistics */
    srgb->stats.alloc_requests++;
    srgb_update_stats(srgb);
    
    return SRGB_OK;
}

srgb_error_t
srgb_alloc_label_dynamic(srgb_t *srgb,
                         srgb_client_t client,
                         void *user_data,
                         uint32_t *label_out,
                         uint32_t *index_out)
{
    uint32_t index;
    srgb_error_t rc;
    
    /* Validate parameters */
    if (!srgb || !label_out) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    /* Find first available index */
    uint16_t idx16 = bitmap_get_unset_bit(&srgb->label_bitmap);
    
    if (idx16 == UINT16_MAX || idx16 >= srgb->range_size) {
        srgb->stats.alloc_failures++;
        return SRGB_ERR_NO_LABELS_AVAILABLE;
    }
    
    index = (uint32_t)idx16;
    
    /* Allocate the label */
    rc = srgb_alloc_label_by_index(srgb, index, client, user_data, label_out);
    if (rc != SRGB_OK) {
        return rc;
    }
    
    if (index_out) {
        *index_out = index;
    }
    
    return SRGB_OK;
}

srgb_error_t
srgb_free_label(srgb_t *srgb, uint32_t label, srgb_client_t client)
{
    uint32_t index;
    srgb_label_entry_t *entry;
    
    /* Validate parameters */
    if (!srgb) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    if (!srgb_is_label_in_range(srgb, label)) {
        return SRGB_ERR_LABEL_OUT_OF_RANGE;
    }
    
    /* Get index */
    index = srgb_label_to_table_index(srgb, label);
    
    /* Check if label is allocated */
    if (!bitmap_at(&srgb->label_bitmap, index)) {
        return SRGB_ERR_LABEL_NOT_ALLOCATED;
    }
    
    /* Verify client ownership */
    entry = &srgb->label_table[index];
    if (entry->client != client) {
        return SRGB_ERR_INVALID_OPERATION;
    }
    
    /* Free the label */
    bitmap_unset_bit_at(&srgb->label_bitmap, index);
    
    /* Clear label table entry */
    memset(entry, 0, sizeof(srgb_label_entry_t));
    
    /* Update statistics */
    srgb->stats.free_requests++;
    srgb_update_stats(srgb);
    
    return SRGB_OK;
}

srgb_error_t
srgb_free_label_by_index(srgb_t *srgb, uint32_t index, srgb_client_t client)
{
    uint32_t label;
    srgb_error_t rc;
    
    if (!srgb) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    if (!srgb_is_index_valid(srgb, index)) {
        return SRGB_ERR_INDEX_OUT_OF_RANGE;
    }
    
    /* Convert index to label */
    rc = srgb_index_to_label(srgb, index, &label);
    if (rc != SRGB_OK) {
        return rc;
    }
    
    /* Free the label */
    return srgb_free_label(srgb, label, client);
}

srgb_error_t
srgb_free_all_labels_by_client(srgb_t *srgb, srgb_client_t client)
{
    uint32_t i;
    srgb_label_entry_t *entry;
    
    if (!srgb) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    /* Iterate through all labels */
    for (i = 0; i < srgb->range_size; i++) {
        entry = &srgb->label_table[i];
        
        if (entry->allocated && entry->client == client) {
            /* Free this label */
            bitmap_unset_bit_at(&srgb->label_bitmap, i);
            memset(entry, 0, sizeof(srgb_label_entry_t));
            srgb->stats.free_requests++;
        }
    }
    
    /* Update statistics */
    srgb_update_stats(srgb);
    
    return SRGB_OK;
}

/* ========================================================================
 * Query and Validation Functions
 * ======================================================================== */

bool
srgb_is_label_in_range(srgb_t *srgb, uint32_t label)
{
    if (!srgb) {
        return false;
    }
    
    return (label >= srgb->base_label && label <= srgb->end_label);
}

bool
srgb_is_index_valid(srgb_t *srgb, uint32_t index)
{
    if (!srgb) {
        return false;
    }
    
    return (index < srgb->range_size);
}

bool
srgb_is_label_allocated(srgb_t *srgb, uint32_t label)
{
    uint32_t index;
    
    if (!srgb || !srgb_is_label_in_range(srgb, label)) {
        return false;
    }
    
    index = srgb_label_to_table_index(srgb, label);
    return bitmap_at(&srgb->label_bitmap, index);
}

srgb_error_t
srgb_get_label_info(srgb_t *srgb, uint32_t label, srgb_label_info_t *info_out)
{
    uint32_t index;
    srgb_label_entry_t *entry;
    
    if (!srgb || !info_out) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    if (!srgb_is_label_in_range(srgb, label)) {
        return SRGB_ERR_LABEL_OUT_OF_RANGE;
    }
    
    index = srgb_label_to_table_index(srgb, label);
    
    if (!bitmap_at(&srgb->label_bitmap, index)) {
        return SRGB_ERR_LABEL_NOT_ALLOCATED;
    }
    
    entry = &srgb->label_table[index];
    
    info_out->label = label;
    info_out->index = index;
    info_out->client = entry->client;
    info_out->ref_count = entry->ref_count;
    info_out->user_data = entry->user_data;
    
    return SRGB_OK;
}

/* ========================================================================
 * Conversion Functions
 * ======================================================================== */

srgb_error_t
srgb_index_to_label(srgb_t *srgb, uint32_t index, uint32_t *label_out)
{
    if (!srgb || !label_out) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    if (!srgb_is_index_valid(srgb, index)) {
        return SRGB_ERR_INDEX_OUT_OF_RANGE;
    }
    
    *label_out = srgb->base_label + index;
    return SRGB_OK;
}

srgb_error_t
srgb_label_to_index(srgb_t *srgb, uint32_t label, uint32_t *index_out)
{
    if (!srgb || !index_out) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    if (!srgb_is_label_in_range(srgb, label)) {
        return SRGB_ERR_LABEL_OUT_OF_RANGE;
    }
    
    *index_out = label - srgb->base_label;
    return SRGB_OK;
}

/* ========================================================================
 * Configuration Getters
 * ======================================================================== */

uint32_t
srgb_get_base_label(srgb_t *srgb)
{
    if (!srgb) {
        return 0;
    }
    return srgb->base_label;
}

uint32_t
srgb_get_range_size(srgb_t *srgb)
{
    if (!srgb) {
        return 0;
    }
    return srgb->range_size;
}

uint32_t
srgb_get_end_label(srgb_t *srgb)
{
    if (!srgb) {
        return 0;
    }
    return srgb->end_label;
}

const char *
srgb_get_name(srgb_t *srgb)
{
    if (!srgb) {
        return NULL;
    }
    return srgb->name;
}

/* ========================================================================
 * Statistics and Monitoring
 * ======================================================================== */

srgb_error_t
srgb_get_stats(srgb_t *srgb, srgb_stats_t *stats_out)
{
    if (!srgb || !stats_out) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    /* Update statistics before returning */
    srgb_update_stats(srgb);
    
    memcpy(stats_out, &srgb->stats, sizeof(srgb_stats_t));
    return SRGB_OK;
}

srgb_error_t
srgb_reset_stats(srgb_t *srgb)
{
    if (!srgb) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    /* Keep total/allocated/free counts, reset counters only */
    srgb->stats.alloc_requests = 0;
    srgb->stats.free_requests = 0;
    srgb->stats.alloc_failures = 0;
    
    return SRGB_OK;
}

/* ========================================================================
 * Display and Debugging
 * ======================================================================== */

void
srgb_show(srgb_t *srgb, bool verbose)
{
    uint32_t i, count;
    srgb_label_entry_t *entry;
    
    if (!srgb) {
        cprintf("Error: Invalid SRGB handle\n");
        return;
    }
    
    /* Update statistics */
    srgb_update_stats(srgb);
    
    /* Display header */
    cprintf("\n");
    cprintf("SRGB Configuration and Status\n");
    cprintf("=============================\n");
    cprintf("Name:               %s\n", srgb->name);
    cprintf("Base Label:         %u\n", srgb->base_label);
    cprintf("Range Size:         %u labels\n", srgb->range_size);
    cprintf("End Label:          %u (inclusive)\n", srgb->end_label);
    cprintf("Range:              [%u - %u]\n", srgb->base_label, srgb->end_label);
    cprintf("\n");
    
    /* Display client registration status */
    cprintf("Registered Clients: ");
    if (srgb->registered_clients == 0) {
        cprintf("None\n");
    } else {
        if (srgb->registered_clients & SRGB_CLIENT_ISIS) cprintf("ISIS ");
        if (srgb->registered_clients & SRGB_CLIENT_OSPF) cprintf("OSPF ");
        if (srgb->registered_clients & SRGB_CLIENT_BGP) cprintf("BGP ");
        if (srgb->registered_clients & SRGB_CLIENT_STATIC) cprintf("STATIC ");
        cprintf("\n");
    }
    cprintf("\n");
    
    /* Display statistics */
    cprintf("Statistics:\n");
    cprintf("  Total Labels:     %u\n", srgb->stats.total_labels);
    cprintf("  Allocated:        %u (%.2f%%)\n", 
            srgb->stats.allocated_labels,
            (srgb->stats.total_labels > 0) ? 
                (100.0 * srgb->stats.allocated_labels / srgb->stats.total_labels) : 0.0);
    cprintf("  Free:             %u (%.2f%%)\n",
            srgb->stats.free_labels,
            (srgb->stats.total_labels > 0) ? 
                (100.0 * srgb->stats.free_labels / srgb->stats.total_labels) : 0.0);
    cprintf("  Alloc Requests:   %u\n", srgb->stats.alloc_requests);
    cprintf("  Free Requests:    %u\n", srgb->stats.free_requests);
    cprintf("  Alloc Failures:   %u\n", srgb->stats.alloc_failures);
    cprintf("\n");
    
    /* Verbose mode: show all allocated labels */
    if (verbose && srgb->stats.allocated_labels > 0) {
        cprintf("Allocated Labels:\n");
        cprintf("%-12s %-12s %-12s %-15s\n", 
                "Label", "Index", "RefCount", "Client");
        cprintf("%-12s %-12s %-12s %-15s\n",
                "------------", "------------", "------------", "---------------");
        
        count = 0;
        for (i = 0; i < srgb->range_size && count < srgb->stats.allocated_labels; i++) {
            if (bitmap_at(&srgb->label_bitmap, i)) {
                entry = &srgb->label_table[i];
                cprintf("%-12u %-12u %-12u %-15s\n",
                        srgb->base_label + i,
                        i,
                        entry->ref_count,
                        srgb_client_to_string(entry->client));
                count++;
            }
        }
        cprintf("\n");
    }
}

void
srgb_show_client_labels(srgb_t *srgb, srgb_client_t client)
{
    uint32_t i, count = 0;
    srgb_label_entry_t *entry;
    
    if (!srgb) {
        cprintf("Error: Invalid SRGB handle\n");
        return;
    }
    
    cprintf("\n");
    cprintf("Labels allocated by client: %s\n", srgb_client_to_string(client));
    cprintf("========================================\n");
    cprintf("%-12s %-12s %-12s\n", "Label", "Index", "RefCount");
    cprintf("%-12s %-12s %-12s\n", "------------", "------------", "------------");
    
    for (i = 0; i < srgb->range_size; i++) {
        entry = &srgb->label_table[i];
        if (entry->allocated && entry->client == client) {
            cprintf("%-12u %-12u %-12u\n",
                    srgb->base_label + i,
                    i,
                    entry->ref_count);
            count++;
        }
    }
    
    if (count == 0) {
        cprintf("No labels allocated\n");
    } else {
        cprintf("\nTotal: %u labels\n", count);
    }
    cprintf("\n");
}

/* ========================================================================
 * Utility Functions
 * ======================================================================== */

const char *
srgb_error_to_string(srgb_error_t error)
{
    switch (error) {
        case SRGB_OK:
            return "Success";
        case SRGB_ERR_INVALID_PARAM:
            return "Invalid parameter";
        case SRGB_ERR_ALREADY_EXISTS:
            return "Already exists";
        case SRGB_ERR_NOT_FOUND:
            return "Not found";
        case SRGB_ERR_RANGE_OVERLAP:
            return "Range overlap";
        case SRGB_ERR_LABEL_OUT_OF_RANGE:
            return "Label out of range";
        case SRGB_ERR_INDEX_OUT_OF_RANGE:
            return "Index out of range";
        case SRGB_ERR_LABEL_IN_USE:
            return "Label already in use";
        case SRGB_ERR_LABEL_NOT_ALLOCATED:
            return "Label not allocated";
        case SRGB_ERR_NO_LABELS_AVAILABLE:
            return "No labels available";
        case SRGB_ERR_MEMORY_ALLOCATION:
            return "Memory allocation failed";
        case SRGB_ERR_INVALID_OPERATION:
            return "Invalid operation";
        case SRGB_ERR_CLIENT_NOT_REGISTERED:
            return "Client not registered";
        default:
            return "Unknown error";
    }
}

const char *
srgb_client_to_string(srgb_client_t client)
{
    switch (client) {
        case SRGB_CLIENT_NONE:
            return "None";
        case SRGB_CLIENT_ISIS:
            return "ISIS";
        case SRGB_CLIENT_OSPF:
            return "OSPF";
        case SRGB_CLIENT_BGP:
            return "BGP";
        case SRGB_CLIENT_STATIC:
            return "Static";
        default:
            return "Unknown";
    }
}

srgb_error_t
srgb_validate_range(uint32_t base_label, uint32_t range_size)
{
    /* Check if range size is valid */
    if (range_size == 0 || range_size > SRGB_MAX_RANGE_SIZE) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    /* Check if base label is valid */
    if (base_label < SRGB_MIN_LABEL_VALUE || 
        base_label > SRGB_MAX_LABEL_VALUE) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    /* Check if end label would exceed maximum */
    if (base_label + range_size - 1 > SRGB_MAX_LABEL_VALUE) {
        return SRGB_ERR_INVALID_PARAM;
    }
    
    return SRGB_OK;
}
