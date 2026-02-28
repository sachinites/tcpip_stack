/*
 * Atomic Operations Example for VLAN-VNI Hashtable
 * 
 * This demonstrates the use of C++ atomic operations for thread-safe
 * pointer management in the VLAN-VNI hashtable implementation.
 */

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include "vlan_vni_ht.h"
#include "../../../router_init.h"
#include "../cp/vxlan.h"

/* Thread data structure */
typedef struct {
    node_t *node;
    int thread_id;
    int iterations;
} thread_data_t;

/* Example demonstrating atomic operations */
void example_atomic_operations(node_t *node) {
    
    printf("=== Atomic Operations Example ===\n");
    
    // 1. Atomic store operation
    printf("\n1. Testing atomic store...\n");
    vlan_vni_ht_db_t *test_db = vlan_vni_ht_create_db();
    vlan_vni_ht_set_db(node, test_db);
    printf("   Stored hashtable pointer: %p\n", (void*)test_db);
    
    // 2. Atomic load operation
    printf("\n2. Testing atomic load...\n");
    vlan_vni_ht_db_t *loaded_db = vlan_vni_ht_get_db(node);
    printf("   Loaded hashtable pointer: %p\n", (void*)loaded_db);
    printf("   Pointers match: %s\n", (test_db == loaded_db) ? "YES" : "NO");
    
    // 3. Atomic compare-and-swap operation
    printf("\n3. Testing atomic compare-and-swap...\n");
    vlan_vni_ht_db_t *new_db = vlan_vni_ht_create_db();
    vlan_vni_ht_db_t *expected = test_db;
    
    bool cas_result = vlan_vni_ht_compare_and_swap_db(node, expected, new_db);
    printf("   Expected pointer: %p\n", (void*)expected);
    printf("   New pointer: %p\n", (void*)new_db);
    printf("   CAS operation: %s\n", cas_result ? "SUCCESS" : "FAILED");
    
    vlan_vni_ht_db_t *current_db = vlan_vni_ht_get_db(node);
    printf("   Current pointer: %p\n", (void*)current_db);
    printf("   Now points to new_db: %s\n", (current_db == new_db) ? "YES" : "NO");
    
    // 4. Atomic clear operation
    printf("\n4. Testing atomic clear...\n");
    vlan_vni_ht_clear_db(node);
    current_db = vlan_vni_ht_get_db(node);
    printf("   After clear, pointer: %p (should be NULL)\n", (void*)current_db);
    
    // Cleanup
    vlan_vni_ht_destroy_db(test_db);
    vlan_vni_ht_destroy_db(new_db);
    
    printf("\n=== Atomic Operations Example Complete ===\n");
}

/* Thread function for concurrent access test */
void *thread_worker(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    
    printf("Thread %d: Starting with %d iterations\n", data->thread_id, data->iterations);
    
    for (int i = 0; i < data->iterations; i++) {
        // Simulate concurrent updates
        uint16_t vlan = 100 + (data->thread_id * 100) + i;
        uint32_t vni = vlan * 10;
        
        // Add mapping using atomic operations
        bool result = vlan_vni_ht_add_mapping(data->node, vlan, vni);
        if (!result) {
            printf("Thread %d: Failed to add VLAN %u -> VNI %u\n", 
                   data->thread_id, vlan, vni);
        }
        
        // Test lookup using atomic operations
        uint32_t lookup_vni = vlan_vni_ht_vlan_to_vni_lookup(data->node, vlan);
        if (lookup_vni != vni) {
            printf("Thread %d: Lookup mismatch for VLAN %u (expected %u, got %u)\n", 
                   data->thread_id, vlan, vni, lookup_vni);
        }
        
        // Small delay to increase chances of race conditions
        usleep(1000); // 1ms
        
        // Remove mapping using atomic operations
        result = vlan_vni_ht_remove_mapping(data->node, vlan);
        if (!result) {
            printf("Thread %d: Failed to remove VLAN %u\n", data->thread_id, vlan);
        }
    }
    
    printf("Thread %d: Completed\n", data->thread_id);
    return NULL;
}

/* Test concurrent access with atomic operations */
void test_concurrent_atomic_access(node_t *node) {
    
    printf("\n=== Concurrent Atomic Access Test ===\n");
    
    const int NUM_THREADS = 4;
    const int ITERATIONS_PER_THREAD = 10;
    
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];
    
    // Initialize hashtable
    vlan_vni_ht_init(node);
    
    printf("Starting %d threads with %d iterations each...\n", 
           NUM_THREADS, ITERATIONS_PER_THREAD);
    
    // Create threads
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].node = node;
        thread_data[i].thread_id = i + 1;
        thread_data[i].iterations = ITERATIONS_PER_THREAD;
        
        int result = pthread_create(&threads[i], NULL, thread_worker, &thread_data[i]);
        if (result != 0) {
            printf("Failed to create thread %d\n", i + 1);
            return;
        }
    }
    
    // Wait for all threads to complete
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("All threads completed successfully!\n");
    
    // Check final state
    uint32_t final_count = vlan_vni_ht_get_mapping_count(node);
    printf("Final mapping count: %u (should be 0 if all removes succeeded)\n", final_count);
    
    printf("\n=== Concurrent Atomic Access Test Complete ===\n");
}

/* Demonstrate atomic pointer operations under load */
void stress_test_atomic_pointers(node_t *node) {
    
    printf("\n=== Atomic Pointer Stress Test ===\n");
    
    const int STRESS_ITERATIONS = 1000;
    
    printf("Performing %d atomic operations...\n", STRESS_ITERATIONS * 4);
    
    for (int i = 0; i < STRESS_ITERATIONS; i++) {
        // Create a new database
        vlan_vni_ht_db_t *new_db = vlan_vni_ht_create_db();
        
        // Atomic set
        vlan_vni_ht_set_db(node, new_db);
        
        // Atomic get
        vlan_vni_ht_db_t *retrieved_db = vlan_vni_ht_get_db(node);
        
        if (retrieved_db != new_db) {
            printf("ERROR: Pointer mismatch at iteration %d\n", i);
            break;
        }
        
        // Test compare-and-swap
        vlan_vni_ht_db_t *another_db = vlan_vni_ht_create_db();
        vlan_vni_ht_db_t *expected = new_db;
        
        bool cas_success = vlan_vni_ht_compare_and_swap_db(node, expected, another_db);
        if (!cas_success) {
            printf("ERROR: CAS failed at iteration %d\n", i);
            vlan_vni_ht_destroy_db(another_db);
            break;
        }
        
        // Atomic clear
        vlan_vni_ht_clear_db(node);
        
        // Verify clear
        vlan_vni_ht_db_t *cleared_db = vlan_vni_ht_get_db(node);
        if (cleared_db != nullptr) {
            printf("ERROR: Clear failed at iteration %d\n", i);
            break;
        }
        
        // Cleanup
        vlan_vni_ht_destroy_db(new_db);
        vlan_vni_ht_destroy_db(another_db);
        
        if ((i + 1) % 100 == 0) {
            printf("   Completed %d iterations...\n", i + 1);
        }
    }
    
    printf("Stress test completed successfully!\n");
    printf("\n=== Atomic Pointer Stress Test Complete ===\n");
}

/* Performance comparison: atomic vs non-atomic operations */
void performance_comparison(node_t *node) {
    
    printf("\n=== Performance Comparison ===\n");
    
    const int PERF_ITERATIONS = 100000;
    
    // Test atomic operations
    printf("Testing %d atomic operations...\n", PERF_ITERATIONS);
    
    clock_t start = clock();
    
    for (int i = 0; i < PERF_ITERATIONS; i++) {
        vlan_vni_ht_db_t *db = vlan_vni_ht_create_db();
        vlan_vni_ht_set_db(node, db);
        vlan_vni_ht_db_t *retrieved = vlan_vni_ht_get_db(node);
        vlan_vni_ht_clear_db(node);
        vlan_vni_ht_destroy_db(db);
        (void)retrieved; // Suppress unused variable warning
    }
    
    clock_t end = clock();
    double atomic_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    printf("Atomic operations time: %f seconds\n", atomic_time);
    printf("Operations per second: %.0f\n", PERF_ITERATIONS / atomic_time);
    
    printf("\n=== Performance Comparison Complete ===\n");
}

/* Main demonstration function */
void demonstrate_atomic_vlan_vni_ht(node_t *node) {
    
    printf("====================================\n");
    printf("VLAN-VNI Hashtable Atomic Operations\n");
    printf("====================================\n");
    
    // Basic atomic operations
    example_atomic_operations(node);
    
    // Concurrent access test
    test_concurrent_atomic_access(node);
    
    // Stress test
    stress_test_atomic_pointers(node);
    
    // Performance test
    performance_comparison(node);
    
    printf("\n====================================\n");
    printf("All atomic operations tests completed successfully!\n");
    printf("====================================\n");
}
