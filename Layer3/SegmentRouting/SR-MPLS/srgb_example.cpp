/*
 * =====================================================================================
 *
 *       Filename:  srgb_example.cpp
 *
 *    Description:  Example usage of SRGB library for SR-MPLS
 *
 *        This file demonstrates how ISIS and OSPF can use the SRGB library
 *        for Segment Routing label management.
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
#include "srgb.h"

/* ========================================================================
 * Example 1: Basic SRGB Operations
 * ======================================================================== */

void example_basic_operations(void)
{
    srgb_t *srgb = NULL;
    srgb_error_t rc;
    uint32_t label;
    uint32_t index;
    
    printf("\n=== Example 1: Basic SRGB Operations ===\n");
    
    /* Create SRGB with standard range */
    rc = srgb_create(16000, 8000, "Example-SRGB", &srgb);
    if (rc != SRGB_OK) {
        printf("Failed to create SRGB: %s\n", srgb_error_to_string(rc));
        return;
    }
    
    printf("✓ Created SRGB: [%u - %u]\n", 
           srgb_get_base_label(srgb), srgb_get_end_label(srgb));
    
    /* Allocate label by index */
    rc = srgb_alloc_label_by_index(srgb, 100, SRGB_CLIENT_ISIS, NULL, &label);
    if (rc == SRGB_OK) {
        printf("✓ Allocated label by index 100: Label = %u\n", label);
    }
    
    /* Allocate dynamic label */
    rc = srgb_alloc_label_dynamic(srgb, SRGB_CLIENT_ISIS, NULL, &label, &index);
    if (rc == SRGB_OK) {
        printf("✓ Allocated dynamic label: Label = %u, Index = %u\n", label, index);
    }
    
    /* Convert index to label */
    srgb_index_to_label(srgb, 200, &label);
    printf("✓ Index 200 → Label %u\n", label);
    
    /* Convert label to index */
    srgb_label_to_index(srgb, 16500, &index);
    printf("✓ Label 16500 → Index %u\n", index);
    
    /* Show statistics */
    srgb_stats_t stats;
    srgb_get_stats(srgb, &stats);
    printf("✓ Statistics: Total=%u, Allocated=%u, Free=%u\n",
           stats.total_labels, stats.allocated_labels, stats.free_labels);
    
    /* Cleanup */
    srgb_destroy(srgb);
    printf("✓ SRGB destroyed\n");
}

/* ========================================================================
 * Example 2: ISIS Integration - Prefix SID Management
 * ======================================================================== */

typedef struct isis_node_sid_ {
    uint32_t router_id;
    uint32_t sid_index;
    uint32_t mpls_label;
    bool is_allocated;
} isis_node_sid_t;

void example_isis_prefix_sids(void)
{
    srgb_t *srgb = NULL;
    srgb_error_t rc;
    isis_node_sid_t nodes[5];
    int i;
    
    printf("\n=== Example 2: ISIS Prefix SID Management ===\n");
    
    /* Create SRGB for ISIS */
    rc = srgb_create(16000, 8000, "ISIS-SRGB", &srgb);
    if (rc != SRGB_OK) {
        printf("Failed to create SRGB\n");
        return;
    }
    
    /* Register ISIS as client */
    srgb_register_client(srgb, SRGB_CLIENT_ISIS);
    printf("✓ ISIS registered as SRGB client\n");
    
    /* Simulate 5 routers in ISIS domain */
    uint32_t router_ids[5] = {
        0x0A0A0A01,  // 10.10.10.1
        0x0A0A0A02,  // 10.10.10.2
        0x0A0A0A03,  // 10.10.10.3
        0x0A0A0A04,  // 10.10.10.4
        0x0A0A0A05   // 10.10.10.5
    };
    
    printf("\nAllocating Prefix SIDs for routers:\n");
    
    for (i = 0; i < 5; i++) {
        nodes[i].router_id = router_ids[i];
        /* Use last octet of router ID as SID index */
        nodes[i].sid_index = router_ids[i] & 0xFF;
        
        rc = srgb_alloc_label_by_index(srgb, nodes[i].sid_index, 
                                        SRGB_CLIENT_ISIS, 
                                        &nodes[i],
                                        &nodes[i].mpls_label);
        
        if (rc == SRGB_OK) {
            nodes[i].is_allocated = true;
            printf("  Router %u.%u.%u.%u: Index=%3u → Label=%u\n",
                   (router_ids[i] >> 24) & 0xFF,
                   (router_ids[i] >> 16) & 0xFF,
                   (router_ids[i] >> 8) & 0xFF,
                   router_ids[i] & 0xFF,
                   nodes[i].sid_index,
                   nodes[i].mpls_label);
        } else {
            nodes[i].is_allocated = false;
            printf("  Failed to allocate for router %d: %s\n", 
                   i + 1, srgb_error_to_string(rc));
        }
    }
    
    /* Show ISIS label allocations */
    printf("\n");
    srgb_show_client_labels(srgb, SRGB_CLIENT_ISIS);
    
    /* Free labels for router 3 (simulating router leaving domain) */
    if (nodes[2].is_allocated) {
        srgb_free_label(srgb, nodes[2].mpls_label, SRGB_CLIENT_ISIS);
        printf("✓ Freed label for router 10.10.10.3\n");
    }
    
    /* Cleanup */
    srgb_unregister_client(srgb, SRGB_CLIENT_ISIS);
    srgb_destroy(srgb);
}

/* ========================================================================
 * Example 3: Multi-Client Scenario (ISIS + OSPF)
 * ======================================================================== */

void example_multi_client(void)
{
    srgb_t *srgb = NULL;
    srgb_error_t rc;
    uint32_t isis_label, ospf_label;
    
    printf("\n=== Example 3: Multi-Client Scenario ===\n");
    
    /* Create shared SRGB */
    rc = srgb_create(16000, 8000, "Shared-SRGB", &srgb);
    if (rc != SRGB_OK) {
        printf("Failed to create SRGB\n");
        return;
    }
    
    /* Register both ISIS and OSPF */
    srgb_register_client(srgb, SRGB_CLIENT_ISIS);
    srgb_register_client(srgb, SRGB_CLIENT_OSPF);
    printf("✓ Registered ISIS and OSPF clients\n");
    
    /* ISIS allocates prefix SID */
    rc = srgb_alloc_label_by_index(srgb, 100, SRGB_CLIENT_ISIS, 
                                    NULL, &isis_label);
    if (rc == SRGB_OK) {
        printf("✓ ISIS allocated: Index=100 → Label=%u\n", isis_label);
    }
    
    /* OSPF allocates different prefix SID */
    rc = srgb_alloc_label_by_index(srgb, 200, SRGB_CLIENT_OSPF, 
                                    NULL, &ospf_label);
    if (rc == SRGB_OK) {
        printf("✓ OSPF allocated: Index=200 → Label=%u\n", ospf_label);
    }
    
    /* Try to allocate same index (should fail) */
    uint32_t dup_label;
    rc = srgb_alloc_label_by_index(srgb, 100, SRGB_CLIENT_OSPF, 
                                    NULL, &dup_label);
    if (rc != SRGB_OK) {
        printf("✓ Correctly prevented duplicate allocation: %s\n",
               srgb_error_to_string(rc));
    }
    
    /* Show allocations per client */
    printf("\n");
    srgb_show_client_labels(srgb, SRGB_CLIENT_ISIS);
    srgb_show_client_labels(srgb, SRGB_CLIENT_OSPF);
    
    /* Show overall SRGB status */
    srgb_show(srgb, false);
    
    /* Cleanup */
    srgb_unregister_client(srgb, SRGB_CLIENT_ISIS);
    srgb_unregister_client(srgb, SRGB_CLIENT_OSPF);
    srgb_destroy(srgb);
}

/* ========================================================================
 * Example 4: Adjacency SID Allocation
 * ======================================================================== */

typedef struct isis_adjacency_ {
    uint32_t ifindex;
    char if_name[16];
    uint32_t adj_sid_label;
    uint32_t adj_sid_index;
} isis_adjacency_t;

void example_adjacency_sids(void)
{
    srgb_t *srgb = NULL;
    srgb_error_t rc;
    isis_adjacency_t adjacencies[3];
    int i;
    
    printf("\n=== Example 4: Adjacency SID Allocation ===\n");
    
    /* Create SRGB */
    rc = srgb_create(16000, 8000, "ISIS-Adj-SRGB", &srgb);
    if (rc != SRGB_OK) {
        printf("Failed to create SRGB\n");
        return;
    }
    
    srgb_register_client(srgb, SRGB_CLIENT_ISIS);
    
    /* Simulate 3 adjacencies */
    strcpy(adjacencies[0].if_name, "eth0");
    strcpy(adjacencies[1].if_name, "eth1");
    strcpy(adjacencies[2].if_name, "eth2");
    
    adjacencies[0].ifindex = 1;
    adjacencies[1].ifindex = 2;
    adjacencies[2].ifindex = 3;
    
    printf("Allocating dynamic Adjacency SIDs:\n");
    
    for (i = 0; i < 3; i++) {
        /* Allocate dynamic label for adjacency SID */
        rc = srgb_alloc_label_dynamic(srgb, SRGB_CLIENT_ISIS,
                                      &adjacencies[i],
                                      &adjacencies[i].adj_sid_label,
                                      &adjacencies[i].adj_sid_index);
        
        if (rc == SRGB_OK) {
            printf("  %s (ifindex=%u): Label=%u, Index=%u\n",
                   adjacencies[i].if_name,
                   adjacencies[i].ifindex,
                   adjacencies[i].adj_sid_label,
                   adjacencies[i].adj_sid_index);
        }
    }
    
    /* Verify allocations */
    srgb_label_info_t info;
    if (srgb_get_label_info(srgb, adjacencies[0].adj_sid_label, &info) == SRGB_OK) {
        printf("\n✓ Label info for %s: Index=%u, Client=%s\n",
               adjacencies[0].if_name,
               info.index,
               srgb_client_to_string(info.client));
    }
    
    /* Cleanup */
    srgb_destroy(srgb);
}

/* ========================================================================
 * Example 5: Error Handling
 * ======================================================================== */

void example_error_handling(void)
{
    srgb_t *srgb = NULL;
    srgb_error_t rc;
    uint32_t label;
    
    printf("\n=== Example 5: Error Handling ===\n");
    
    /* Create SRGB */
    srgb_create(16000, 8000, "Error-Test-SRGB", &srgb);
    
    /* Try to allocate without registering client */
    rc = srgb_alloc_label_by_index(srgb, 100, SRGB_CLIENT_ISIS, NULL, &label);
    printf("Allocation without registration: %s\n", srgb_error_to_string(rc));
    
    /* Register and allocate */
    srgb_register_client(srgb, SRGB_CLIENT_ISIS);
    srgb_alloc_label_by_index(srgb, 100, SRGB_CLIENT_ISIS, NULL, &label);
    
    /* Try to allocate same index again */
    rc = srgb_alloc_label_by_index(srgb, 100, SRGB_CLIENT_ISIS, NULL, &label);
    printf("Duplicate allocation: %s ✓\n", srgb_error_to_string(rc));
    
    /* Try out-of-range index */
    rc = srgb_alloc_label_by_index(srgb, 10000, SRGB_CLIENT_ISIS, NULL, &label);
    printf("Out of range index: %s ✓\n", srgb_error_to_string(rc));
    
    /* Try to free unallocated label */
    rc = srgb_free_label(srgb, 16500, SRGB_CLIENT_ISIS);
    printf("Free unallocated label: %s ✓\n", srgb_error_to_string(rc));
    
    /* Try invalid range configuration */
    srgb_t *bad_srgb = NULL;
    rc = srgb_create(5, 1000, "Bad-SRGB", &bad_srgb);
    printf("Invalid SRGB range (base=5): %s ✓\n", srgb_error_to_string(rc));
    
    /* Cleanup */
    srgb_destroy(srgb);
}

/* ========================================================================
 * Example 6: Statistics and Monitoring
 * ======================================================================== */

void example_statistics(void)
{
    srgb_t *srgb = NULL;
    srgb_stats_t stats;
    uint32_t label;
    int i;
    
    printf("\n=== Example 6: Statistics and Monitoring ===\n");
    
    /* Create small SRGB for demo */
    srgb_create(16000, 100, "Stats-SRGB", &srgb);
    srgb_register_client(srgb, SRGB_CLIENT_ISIS);
    
    printf("Initial state:\n");
    srgb_get_stats(srgb, &stats);
    printf("  Total: %u, Allocated: %u, Free: %u\n",
           stats.total_labels, stats.allocated_labels, stats.free_labels);
    
    /* Allocate 50 labels */
    for (i = 0; i < 50; i++) {
        srgb_alloc_label_by_index(srgb, i, SRGB_CLIENT_ISIS, NULL, &label);
    }
    
    printf("\nAfter allocating 50 labels:\n");
    srgb_get_stats(srgb, &stats);
    printf("  Total: %u, Allocated: %u (%.1f%%), Free: %u (%.1f%%)\n",
           stats.total_labels,
           stats.allocated_labels,
           100.0 * stats.allocated_labels / stats.total_labels,
           stats.free_labels,
           100.0 * stats.free_labels / stats.total_labels);
    printf("  Allocation requests: %u\n", stats.alloc_requests);
    printf("  Allocation failures: %u\n", stats.alloc_failures);
    
    /* Free 25 labels */
    for (i = 0; i < 25; i++) {
        srgb_index_to_label(srgb, i, &label);
        srgb_free_label(srgb, label, SRGB_CLIENT_ISIS);
    }
    
    printf("\nAfter freeing 25 labels:\n");
    srgb_get_stats(srgb, &stats);
    printf("  Allocated: %u, Free: %u\n",
           stats.allocated_labels, stats.free_labels);
    printf("  Free requests: %u\n", stats.free_requests);
    
    /* Show detailed view */
    printf("\n");
    srgb_show(srgb, true);
    
    /* Cleanup */
    srgb_destroy(srgb);
}

/* ========================================================================
 * Main Function - Run All Examples
 * ======================================================================== */

int main(int argc, char **argv)
{
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║         SRGB Library - Example Usage Demonstrations       ║\n");
    printf("║              Segment Routing Global Block                 ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    
    /* Run all examples */
    example_basic_operations();
    example_isis_prefix_sids();
    example_multi_client();
    example_adjacency_sids();
    example_error_handling();
    example_statistics();
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║                 All Examples Completed                     ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    return 0;
}
