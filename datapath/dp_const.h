#ifndef __DP_CONST__
#define __DP_CONST__

#define DEFAULT_NUMA_NODE 0

/* Grace period (ms) between removing an entry from the hash table and
 * freeing its memory.  Forwarding threads that already hold a pointer to
 * the entry have this window to finish.  Must be >> the longest possible
 * packet-processing latency on any core. */
#define DP_TABLE_GC_DELAY_MS  2000   /* 2 seconds */

/* Grace period (ms) between delinking an interface from intf_table and
 * freeing its memory.  In-flight packets may still hold a pointer to intf
 * during this window. */
#define DP_INTF_DELETE_GRACE_MS  3000   /* 3 seconds */

/* Allocate 10k , increase it as per your FIB scale and
    system HUGE-PAGE memory size. This number do not represent
    max number of routes FIB can hold, but total number of nodes
    in FIB mtrie data structure. Routes are held only in leaf nodes
    of mtrie.*/
#define MAX_FIB_MTRIE_NODES 10000

/* DPDK RX ring depth (must match dp_intf_recv_xmit RX_RING_SIZE). */
#define DP_DPDK_RX_RING_SIZE 1024

/* Lower bound and extra mbufs for stack/TX when sizing per-NUMA mbuf pools. */
#define DP_MBUF_POOL_MIN_ELTS   8192
#define DP_MBUF_POOL_HEADROOM   8192

#endif /* __DP_CONST__ */