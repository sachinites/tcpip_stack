/*
 * =====================================================================================
 *
 *       Filename:  srgb.h
 *
 *    Description:  SRGB (Segment Routing Global Block) Library for SR-MPLS
 *
 *        The SRGB is a contiguous block of MPLS labels reserved for segment routing.
 *        Each router in the SR domain uses the same SRGB range for consistency.
 *        
 *        Key Concepts:
 *        ┌─────────────────────────────────────────────────────────────────┐
 *        │ SRGB: [Base Label ... Base Label + Range Size - 1]            │
 *        │ Example: [16000 ... 23999] (Base=16000, Size=8000)            │
 *        │                                                                 │
 *        │ Label Calculation:                                             │
 *        │   MPLS Label = SRGB Base + SID Index                          │
 *        │   Example: Index 100 → Label 16100                            │
 *        └─────────────────────────────────────────────────────────────────┘
 *
 *        Usage:
 *        - ISIS/OSPF advertise prefix SIDs as indices (e.g., 100)
 *        - Each router computes the label using its SRGB
 *        - Labels are allocated from the SRGB for local prefixes
 *
 *        Version:  1.0
 *        Created:  2026-02-09
 *       Compiler:  gcc/g++
 *
 * =====================================================================================
 */

#ifndef __SRGB_H__
#define __SRGB_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Constants and Limits
 * ======================================================================== */

/* IANA MPLS Label Ranges:
 *   0-15: Reserved labels
 *   16-1023: Reserved for future use
 *   16000-23999: Common SRGB range (default)
 *   1048576: Maximum label value (20 bits)
 */
#define SRGB_MIN_LABEL_VALUE        16
#define SRGB_MAX_LABEL_VALUE        1048575
#define SRGB_DEFAULT_BASE_LABEL     16000
#define SRGB_DEFAULT_RANGE_SIZE     8000
#define SRGB_MAX_RANGE_SIZE         1000000
#define SRGB_MAX_NAME_LEN           64

/* ========================================================================
 * Type Definitions
 * ======================================================================== */

/**
 * @brief SRGB client types (protocols using SRGB)
 */
typedef enum srgb_client_ {
    SRGB_CLIENT_NONE    = 0,
    SRGB_CLIENT_ISIS    = (1 << 0),  /* 0x01 */
    SRGB_CLIENT_OSPF    = (1 << 1),  /* 0x02 */
    SRGB_CLIENT_BGP     = (1 << 2),  /* 0x04 */
    SRGB_CLIENT_STATIC  = (1 << 3),  /* 0x08 */
    SRGB_CLIENT_MAX     = (1 << 4)
} srgb_client_t;

/**
 * @brief Error codes for SRGB operations
 */
typedef enum srgb_error_ {
    SRGB_OK = 0,
    SRGB_ERR_INVALID_PARAM,
    SRGB_ERR_ALREADY_EXISTS,
    SRGB_ERR_NOT_FOUND,
    SRGB_ERR_RANGE_OVERLAP,
    SRGB_ERR_LABEL_OUT_OF_RANGE,
    SRGB_ERR_INDEX_OUT_OF_RANGE,
    SRGB_ERR_LABEL_IN_USE,
    SRGB_ERR_LABEL_NOT_ALLOCATED,
    SRGB_ERR_NO_LABELS_AVAILABLE,
    SRGB_ERR_MEMORY_ALLOCATION,
    SRGB_ERR_INVALID_OPERATION,
    SRGB_ERR_CLIENT_NOT_REGISTERED
} srgb_error_t;

/**
 * @brief Label allocation information
 */
typedef struct srgb_label_info_ {
    uint32_t label;           /* Allocated MPLS label */
    uint32_t index;           /* SID index (offset from base) */
    srgb_client_t client;     /* Client that owns this label */
    uint32_t ref_count;       /* Reference count */
    void *user_data;          /* Client-specific data */
} srgb_label_info_t;

/**
 * @brief SRGB statistics
 */
typedef struct srgb_stats_ {
    uint32_t total_labels;       /* Total labels in SRGB */
    uint32_t allocated_labels;   /* Number of allocated labels */
    uint32_t free_labels;        /* Number of free labels */
    uint32_t alloc_requests;     /* Total allocation requests */
    uint32_t free_requests;      /* Total free requests */
    uint32_t alloc_failures;     /* Failed allocations */
} srgb_stats_t;

/* Forward declaration of opaque SRGB handle */
typedef struct srgb_ srgb_t;

/* ========================================================================
 * SRGB Lifecycle Management
 * ======================================================================== */

/**
 * @brief Create and initialize a new SRGB instance
 * 
 * @param base_label   Starting MPLS label of the SRGB range
 * @param range_size   Number of labels in the range
 * @param name         Optional name for this SRGB instance
 * @param srgb_out     Pointer to store the created SRGB handle
 * 
 * @return SRGB_OK on success, error code otherwise
 */
srgb_error_t
srgb_create(uint32_t base_label, 
            uint32_t range_size,
            const char *name,
            srgb_t **srgb_out);

/**
 * @brief Destroy an SRGB instance and free all resources
 * 
 * @param srgb  SRGB handle to destroy
 * 
 * @return SRGB_OK on success, error code otherwise
 */
srgb_error_t
srgb_destroy(srgb_t *srgb);

/**
 * @brief Reinitialize SRGB with new range (releases all allocations)
 * 
 * @param srgb         SRGB handle
 * @param base_label   New starting MPLS label
 * @param range_size   New range size
 * 
 * @return SRGB_OK on success, error code otherwise
 */
srgb_error_t
srgb_reconfigure(srgb_t *srgb, uint32_t base_label, uint32_t range_size);

/* ========================================================================
 * Client Registration
 * ======================================================================== */

/**
 * @brief Register a client with the SRGB
 * 
 * @param srgb    SRGB handle
 * @param client  Client type to register
 * 
 * @return SRGB_OK on success, error code otherwise
 */
srgb_error_t
srgb_register_client(srgb_t *srgb, srgb_client_t client);

/**
 * @brief Unregister a client (releases all its labels)
 * 
 * @param srgb    SRGB handle
 * @param client  Client type to unregister
 * 
 * @return SRGB_OK on success, error code otherwise
 */
srgb_error_t
srgb_unregister_client(srgb_t *srgb, srgb_client_t client);

/**
 * @brief Check if a client is registered
 * 
 * @param srgb    SRGB handle
 * @param client  Client type to check
 * 
 * @return true if registered, false otherwise
 */
bool
srgb_is_client_registered(srgb_t *srgb, srgb_client_t client);

/* ========================================================================
 * Label Allocation and Management
 * ======================================================================== */

/**
 * @brief Allocate a label by index
 * 
 * Allocates the label at the specified index (offset from SRGB base).
 * Label = base_label + index
 * 
 * @param srgb        SRGB handle
 * @param index       SID index (0 to range_size - 1)
 * @param client      Client requesting the allocation
 * @param user_data   Optional user data to associate with allocation
 * @param label_out   Pointer to store the allocated label
 * 
 * @return SRGB_OK on success, error code otherwise
 */
srgb_error_t
srgb_alloc_label_by_index(srgb_t *srgb,
                          uint32_t index,
                          srgb_client_t client,
                          void *user_data,
                          uint32_t *label_out);

/**
 * @brief Allocate any available label dynamically
 * 
 * @param srgb        SRGB handle
 * @param client      Client requesting the allocation
 * @param user_data   Optional user data to associate with allocation
 * @param label_out   Pointer to store the allocated label
 * @param index_out   Pointer to store the index (can be NULL)
 * 
 * @return SRGB_OK on success, error code otherwise
 */
srgb_error_t
srgb_alloc_label_dynamic(srgb_t *srgb,
                         srgb_client_t client,
                         void *user_data,
                         uint32_t *label_out,
                         uint32_t *index_out);

/**
 * @brief Free a previously allocated label
 * 
 * @param srgb    SRGB handle
 * @param label   Label to free
 * @param client  Client that owns the label
 * 
 * @return SRGB_OK on success, error code otherwise
 */
srgb_error_t
srgb_free_label(srgb_t *srgb, uint32_t label, srgb_client_t client);

/**
 * @brief Free a label by index
 * 
 * @param srgb    SRGB handle
 * @param index   Index to free
 * @param client  Client that owns the label
 * 
 * @return SRGB_OK on success, error code otherwise
 */
srgb_error_t
srgb_free_label_by_index(srgb_t *srgb, uint32_t index, srgb_client_t client);

/**
 * @brief Free all labels allocated by a specific client
 * 
 * @param srgb    SRGB handle
 * @param client  Client whose labels to free
 * 
 * @return SRGB_OK on success, error code otherwise
 */
srgb_error_t
srgb_free_all_labels_by_client(srgb_t *srgb, srgb_client_t client);

/* ========================================================================
 * Query and Validation Functions
 * ======================================================================== */

/**
 * @brief Check if a label is within SRGB range
 * 
 * @param srgb   SRGB handle
 * @param label  Label to check
 * 
 * @return true if in range, false otherwise
 */
bool
srgb_is_label_in_range(srgb_t *srgb, uint32_t label);

/**
 * @brief Check if an index is within valid range
 * 
 * @param srgb   SRGB handle
 * @param index  Index to check
 * 
 * @return true if valid, false otherwise
 */
bool
srgb_is_index_valid(srgb_t *srgb, uint32_t index);

/**
 * @brief Check if a label is currently allocated
 * 
 * @param srgb   SRGB handle
 * @param label  Label to check
 * 
 * @return true if allocated, false otherwise
 */
bool
srgb_is_label_allocated(srgb_t *srgb, uint32_t label);

/**
 * @brief Get information about an allocated label
 * 
 * @param srgb       SRGB handle
 * @param label      Label to query
 * @param info_out   Pointer to store label information
 * 
 * @return SRGB_OK on success, error code otherwise
 */
srgb_error_t
srgb_get_label_info(srgb_t *srgb, uint32_t label, srgb_label_info_t *info_out);

/* ========================================================================
 * Conversion Functions
 * ======================================================================== */

/**
 * @brief Convert index to label
 * 
 * @param srgb        SRGB handle
 * @param index       SID index
 * @param label_out   Pointer to store the label
 * 
 * @return SRGB_OK on success, error code otherwise
 */
srgb_error_t
srgb_index_to_label(srgb_t *srgb, uint32_t index, uint32_t *label_out);

/**
 * @brief Convert label to index
 * 
 * @param srgb        SRGB handle
 * @param label       MPLS label
 * @param index_out   Pointer to store the index
 * 
 * @return SRGB_OK on success, error code otherwise
 */
srgb_error_t
srgb_label_to_index(srgb_t *srgb, uint32_t label, uint32_t *index_out);

/* ========================================================================
 * Configuration Getters
 * ======================================================================== */

/**
 * @brief Get SRGB base label
 * 
 * @param srgb  SRGB handle
 * 
 * @return Base label, or 0 if invalid
 */
uint32_t
srgb_get_base_label(srgb_t *srgb);

/**
 * @brief Get SRGB range size
 * 
 * @param srgb  SRGB handle
 * 
 * @return Range size, or 0 if invalid
 */
uint32_t
srgb_get_range_size(srgb_t *srgb);

/**
 * @brief Get SRGB end label (inclusive)
 * 
 * @param srgb  SRGB handle
 * 
 * @return End label, or 0 if invalid
 */
uint32_t
srgb_get_end_label(srgb_t *srgb);

/**
 * @brief Get SRGB name
 * 
 * @param srgb  SRGB handle
 * 
 * @return Name string, or NULL if invalid
 */
const char *
srgb_get_name(srgb_t *srgb);

/* ========================================================================
 * Statistics and Monitoring
 * ======================================================================== */

/**
 * @brief Get SRGB statistics
 * 
 * @param srgb       SRGB handle
 * @param stats_out  Pointer to store statistics
 * 
 * @return SRGB_OK on success, error code otherwise
 */
srgb_error_t
srgb_get_stats(srgb_t *srgb, srgb_stats_t *stats_out);

/**
 * @brief Reset SRGB statistics counters
 * 
 * @param srgb  SRGB handle
 * 
 * @return SRGB_OK on success, error code otherwise
 */
srgb_error_t
srgb_reset_stats(srgb_t *srgb);

/* ========================================================================
 * Display and Debugging
 * ======================================================================== */

/**
 * @brief Display SRGB configuration and status
 * 
 * @param srgb     SRGB handle
 * @param verbose  If true, show detailed allocation info
 */
void
srgb_show(srgb_t *srgb, bool verbose);

/**
 * @brief Display all labels allocated by a specific client
 * 
 * @param srgb    SRGB handle
 * @param client  Client to show
 */
void
srgb_show_client_labels(srgb_t *srgb, srgb_client_t client);

/* ========================================================================
 * Utility Functions
 * ======================================================================== */

/**
 * @brief Convert error code to string
 * 
 * @param error  Error code
 * 
 * @return Error string description
 */
const char *
srgb_error_to_string(srgb_error_t error);

/**
 * @brief Convert client type to string
 * 
 * @param client  Client type
 * 
 * @return Client name string
 */
const char *
srgb_client_to_string(srgb_client_t client);

/**
 * @brief Validate SRGB range parameters
 * 
 * @param base_label  Base label to validate
 * @param range_size  Range size to validate
 * 
 * @return SRGB_OK if valid, error code otherwise
 */
srgb_error_t
srgb_validate_range(uint32_t base_label, uint32_t range_size);

#ifdef __cplusplus
}
#endif

#endif /* __SRGB_H__ */
