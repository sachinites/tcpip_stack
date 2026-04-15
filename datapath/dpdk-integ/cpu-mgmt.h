#ifndef __CPU_MGMT__
#define __CPU_MGMT__

#include <stdint.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>

/* Data structure to represent a Logical core on the System */

typedef enum lcore_state_ {

    WAIT,
    RUNNING

} lcore_state_t;

typedef enum lcore_role_ {

    ROLE_CONTROL_PLANE,
    ROLE_DATA_PLANE

} lcore_role_t;

#pragma pack(push, 8)

/* This structure is same as 'struct lcore_config' in dpdk */
typedef struct lcore_config_ {

    /* Every logical core has an id starting from 0 */
    uint16_t lcore_id;

    /* Every lcore runs a thread, it is that thread id*/
    pthread_t thread_id;

    /* Lcore threads needs to communicate with Control plane
        thread (a.k.a main thread) Bidirectionally. index 0 is read
        end of pipe and index 1 is write end of pipe */
    int pipe_main2worker[2];   /**< communication pipe with main */
	int pipe_worker2main[2];   /**< communication pipe with main */

    /* fn to run as thread fn */
    int (*lcore_function)(void *); 
    void *fn_arg;

    /* socket id this lcore sits on*/
    uint32_t socket_id;

    /* core-id of this logical core. In most systems, on each core
    two lcore runs Or just 1*/
    uint32_t core_id;

    /* Relative index starting from zero
    So, if cores are as below, and only cores C1, C5 and C7 are used, 
    then index would be as what is written underneath
    C0 C1 C2 C3 C4 C5 C6 C7 
    -1 0 -1  -1 -1  1 -1  2   */
    int core_index;

    /* Role of this LCore */
    lcore_state_t lcore_role;

    /* Role of this LCore*/
    lcore_state_t state;

    /* The thread running on this Lcore, can be scheduled on this CPUset. 
    This CPUSet would contain only 1 CPU so, its essentially a 1:1 thread pinning. */
    cpu_set_t cpuset;

} lcore_config_t;

#pragma pack(pop)

/* Equivalent to rte_eal_cpu_init() */
int lcore_init(void);

#endif 