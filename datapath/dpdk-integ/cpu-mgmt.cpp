#include "cpu-mgmt.h"
#include "dp_const.h"

//eal_cpu_socket_id
#include <eal_thread.h> 
//eal_cpu_detected
#include <eal_private.h>

/* Global data structure to store Lcores info */
lcore_config_t lcore_config[MAX_LCORE_SUPPORTED] = {0};
int16_t numa_nodes[MAX_NUMA_NODES] = {-1};

void 
cpu_init(void) {

    uint32_t lcore_id;
    lcore_config_t *lcore;
    int count = 0;

    for (lcore_id = 0; lcore_id < MAX_LCORE_SUPPORTED; lcore_id++) {

        lcore = &lcore_config[lcore_id];
        
        /* Detect the CPU of this lcore */
		if (eal_cpu_detected(lcore_id) == 0) {
			lcore->lcore_role = ROLE_OFF;
			lcore->core_index = -1;
			continue;
		}

        /* Assign relative core index*/
        lcore->core_index = count++;

        /* Find the Socket ID of this Lcore */
        lcore->socket_id = eal_cpu_socket_id(lcore_id);

        /* Pin the lcore thread to the CPU Set, this is 1:1 mapping
        That is lcore thread x will run on cpu x */
        CPU_ZERO(&lcore->cpuset);
        CPU_SET(lcore_id, &lcore->cpuset);

        /* Not that, lcore as been assined a CPU, mark the lcore theread as in use */
        lcore->lcore_role = ROLE_IN_USE;

        /* Assign a core id to this lcore */
        lcore->core_id = eal_cpu_core_id(lcore_id);
    }

}

void 
numa_nodes_init (void) {

}