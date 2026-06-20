#ifndef __DP_CONST__
#define __DP_CONST__

#define DEFAULT_NUMA_NODE 0

/* Grace period (ms) between removing an entry from the hash table and
 * freeing its memory.  Forwarding threads that already hold a pointer to
 * the entry have this window to finish.  Must be >> the longest possible
 * packet-processing latency on any core. */
#define DP_TABLE_GC_DELAY_MS  2000   /* 2 seconds */

/* Allocate 10k , increase it as per your FIB scale and
    system HUGE-PAGE memory size. This number do not represent
    max number of routes FIB can hold, but total number of nodes
    in FIB mtrie data structure. Routes are held only in leaf nodes
    of mtrie.*/
#define MAX_FIB_MTRIE_NODES 10000


#endif /* __DP_CONST__ */