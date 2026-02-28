/*
 * Example usage of VLAN-VNI Hashtable functionality
 * 
 * This file demonstrates how to use the new O(1) hashtable-based
 * VLAN-VNI lookup functionality.
 */

#include <stdio.h>
#include "vlan_vni_ht.h"
#include "../../../router_init.h"
#include "../cp/vxlan.h"

void example_vlan_vni_hashtable_usage(node_t *node) {
    
    printf("=== VLAN-VNI Hashtable Example ===\n");
    
    // Add some VLAN-VNI mappings to the control plane database first
    printf("Adding VLAN-VNI mappings to control plane database...\n");
    vlan_vni_add_mapping(node, 100, 1000);
    vlan_vni_add_mapping(node, 200, 2000);
    vlan_vni_add_mapping(node, 300, 3000);
    
    // The hashtable is automatically synchronized when mappings are added
    printf("Hashtable synchronized automatically.\n");
    
    // Test O(1) lookups
    printf("\n=== O(1) Lookup Tests ===\n");
    
    uint32_t vni;
    uint16_t vlan;
    
    // VLAN to VNI lookups
    vni = vlan_vni_ht_vlan_to_vni_lookup(node, 100);
    printf("VLAN 100 -> VNI %u\n", vni);
    
    vni = vlan_vni_ht_vlan_to_vni_lookup(node, 200);
    printf("VLAN 200 -> VNI %u\n", vni);
    
    vni = vlan_vni_ht_vlan_to_vni_lookup(node, 999); // Should return 0
    printf("VLAN 999 -> VNI %u (not found)\n", vni);
    
    // VNI to VLAN lookups
    vlan = vlan_vni_ht_vni_to_vlan_lookup(node, 1000);
    printf("VNI 1000 -> VLAN %u\n", vlan);
    
    vlan = vlan_vni_ht_vni_to_vlan_lookup(node, 2000);
    printf("VNI 2000 -> VLAN %u\n", vlan);
    
    vlan = vlan_vni_ht_vni_to_vlan_lookup(node, 9999); // Should return 0
    printf("VNI 9999 -> VLAN %u (not found)\n", vlan);
    
    // Display statistics
    printf("\n=== Statistics ===\n");
    printf("Total mappings: %u\n", vlan_vni_ht_get_mapping_count(node));
    vlan_vni_ht_dump_mappings(node);
    
    // Remove a mapping and test again
    printf("\n=== Testing removal ===\n");
    printf("Removing VLAN 200 mapping...\n");
    vlan_vni_remove_mapping(node, 200);
    
    vni = vlan_vni_ht_vlan_to_vni_lookup(node, 200);
    printf("VLAN 200 -> VNI %u (should be 0 after removal)\n", vni);
    
    printf("Total mappings after removal: %u\n", vlan_vni_ht_get_mapping_count(node));
    
    printf("\n=== Example completed ===\n");
}

/* 
 * Performance comparison function
 * This demonstrates the performance difference between O(n) linear search
 * and O(1) hashtable lookup
 */
void performance_comparison_example(node_t *node) {
    
    printf("\n=== Performance Comparison ===\n");
    
    // Add many mappings
    printf("Adding 1000 VLAN-VNI mappings...\n");
    for (int i = 1; i <= 1000; i++) {
        vlan_vni_add_mapping(node, i, i * 10);
    }
    
    printf("Testing lookup performance...\n");
    
    // Test hashtable lookup (O(1))
    uint32_t vni = vlan_vni_ht_vlan_to_vni_lookup(node, 999);
    printf("Hashtable lookup (O(1)): VLAN 999 -> VNI %u\n", vni);
    
    // Test control plane lookup (O(n))
    vni = vlan_to_vni_lookup(node, 999);
    printf("Control plane lookup (O(n)): VLAN 999 -> VNI %u\n", vni);
    
    printf("Both should return the same result, but hashtable is much faster!\n");
    printf("Performance improvement is significant for large numbers of mappings.\n");
}

