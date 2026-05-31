#ifndef __DP_CONST__
#define __DP_CONST__

#define DEFAULT_NUMA_NODE 0

/* Allocate 10k , increase it as per your FIB scale and
    system HUGE-PAGE memory size. This number do not represent
    max number of routes FIB can hold, but total number of nodes
    in FIB mtrie data structure. Routes are held only in leaf nodes
    of mtrie.*/
#define MAX_FIB_MTRIE_NODES 10000


#endif /* __DP_CONST__ */