/*
 * Example usage of optimized VLAN-VNI Hashtable functions
 * 
 * This demonstrates the new atomic update approach that directly
 * modifies hashtable entries without rebuilding from control plane database.
 */

#include <stdio.h>
#include "vlan_vni_ht.h"
#include "../../../router_init.h"
#include "../cp/vxlan.h"

void example_optimized_atomic_updates(node_t *node) {
    
    printf("=== Optimized Atomic VLAN-VNI Hashtable Updates ===\n");
    
    // Test adding mappings with direct hashtable updates
    printf("\n1. Adding VLAN-VNI mappings with atomic updates...\n");
    
    bool result;
    result = vlan_vni_ht_add_mapping(node, 100, 1000);
    printf("   Add VLAN 100 -> VNI 1000: %s\n", result ? "SUCCESS" : "FAILED");
    
    result = vlan_vni_ht_add_mapping(node, 200, 2000);
    printf("   Add VLAN 200 -> VNI 2000: %s\n", result ? "SUCCESS" : "FAILED");
    
    result = vlan_vni_ht_add_mapping(node, 300, 3000);
    printf("   Add VLAN 300 -> VNI 3000: %s\n", result ? "SUCCESS" : "FAILED");
    
    // Test lookups
    printf("\n2. Testing O(1) lookups after atomic updates...\n");
    uint32_t vni = vlan_vni_ht_vlan_to_vni_lookup(node, 100);
    printf("   VLAN 100 -> VNI %u\n", vni);
    
    uint16_t vlan = vlan_vni_ht_vni_to_vlan_lookup(node, 2000);
    printf("   VNI 2000 -> VLAN %u\n", vlan);
    
    // Test updating existing mapping
    printf("\n3. Testing update of existing mapping...\n");
    result = vlan_vni_ht_add_mapping(node, 100, 1500); // Update VLAN 100 to new VNI
    printf("   Update VLAN 100 -> VNI 1500: %s\n", result ? "SUCCESS" : "FAILED");
    
    vni = vlan_vni_ht_vlan_to_vni_lookup(node, 100);
    printf("   VLAN 100 now maps to VNI %u\n", vni);
    
    // Test removing by VLAN
    printf("\n4. Testing removal by VLAN...\n");
    result = vlan_vni_ht_remove_mapping(node, 200);
    printf("   Remove VLAN 200: %s\n", result ? "SUCCESS" : "FAILED");
    
    vni = vlan_vni_ht_vlan_to_vni_lookup(node, 200);
    printf("   VLAN 200 now maps to VNI %u (should be 0)\n", vni);
    
    // Test removing by VNI
    printf("\n5. Testing removal by VNI...\n");
    result = vlan_vni_ht_remove_mapping_by_vni(node, 3000);
    printf("   Remove VNI 3000: %s\n", result ? "SUCCESS" : "FAILED");
    
    vlan = vlan_vni_ht_vni_to_vlan_lookup(node, 3000);
    printf("   VNI 3000 now maps to VLAN %u (should be 0)\n", vlan);
    
    // Show final statistics
    printf("\n6. Final statistics...\n");
    printf("   Total mappings: %u\n", vlan_vni_ht_get_mapping_count(node));
    vlan_vni_ht_dump_mappings(node);
    
    printf("\n=== Atomic Updates Example Completed ===\n");
}

void example_atomic_update_process(node_t *node) {
    
    printf("\n=== Atomic Update Process Demonstration ===\n");
    printf("This demonstrates the step-by-step atomic update process:\n");
    
    printf("\n1. Initial state: No hashtables\n");
    printf("   Hashtable pointer: %p\n", (void*)vlan_vni_ht_get_db(node));
    
    printf("\n2. Adding first mapping - creates hashtable\n");
    vlan_vni_ht_add_mapping(node, 100, 1000);
    printf("   Hashtable pointer: %p\n", (void*)vlan_vni_ht_get_db(node));
    printf("   Entry count: %u\n", vlan_vni_ht_get_mapping_count(node));
    
    printf("\n3. Adding second mapping - updates existing hashtable\n");
    void *old_ptr = (void*)vlan_vni_ht_get_db(node);
    vlan_vni_ht_add_mapping(node, 200, 2000);
    void *new_ptr = (void*)vlan_vni_ht_get_db(node);
    printf("   Old hashtable pointer: %p\n", old_ptr);
    printf("   New hashtable pointer: %p (same - in-place update)\n", new_ptr);
    printf("   Entry count: %u\n", vlan_vni_ht_get_mapping_count(node));
    
    printf("\n4. Removing mapping - updates existing hashtable\n");
    old_ptr = (void*)vlan_vni_ht_get_db(node);
    vlan_vni_ht_remove_mapping(node, 100);
    new_ptr = (void*)vlan_vni_ht_get_db(node);
    printf("   Old hashtable pointer: %p\n", old_ptr);
    printf("   New hashtable pointer: %p (same - in-place update)\n", new_ptr);
    printf("   Entry count: %u\n", vlan_vni_ht_get_mapping_count(node));
    
    printf("\n=== Atomic Update Process Complete ===\n");
}

void performance_test_optimized(node_t *node) {
    
    printf("\n=== Performance Test: Optimized vs Control Plane ===\n");
    
    // Add many mappings using optimized functions
    printf("Adding 100 mappings using optimized hashtable functions...\n");
    clock_t start = clock();
    
    for (int i = 1; i <= 100; i++) {
        vlan_vni_ht_add_mapping(node, i, i * 10);
    }
    
    clock_t end = clock();
    double optimized_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Time taken: %f seconds\n", optimized_time);
    
    // Test lookup performance
    printf("\nTesting lookup performance...\n");
    start = clock();
    
    for (int i = 1; i <= 100; i++) {
        uint32_t vni = vlan_vni_ht_vlan_to_vni_lookup(node, i);
        (void)vni; // Suppress unused variable warning
    }
    
    end = clock();
    double lookup_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("100 O(1) lookups took: %f seconds\n", lookup_time);
    
    printf("Final mapping count: %u\n", vlan_vni_ht_get_mapping_count(node));
    
    printf("\n=== Performance Test Complete ===\n");
}
