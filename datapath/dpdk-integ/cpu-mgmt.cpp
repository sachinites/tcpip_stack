#include "cpu-mgmt.h"
#include "dp_const.h"

//eal_cpu_socket_id
#include <eal_thread.h> 
//eal_cpu_detected
#include <eal_private.h>

#include <semaphore.h>

/* Global data structure to store Lcores info */
lcore_config_t lcore_config[MAX_LCORE_SUPPORTED] = {0};

extern int cprintf (const char *format, ...);
extern void *controlplane_thread_function(void *arg);
extern void *data_path_thread_function(void *arg);


static void 
control_plane_thread_setup (lcore_config_t *lcore, sem_t *init_wait_sema) {

    lcore->lcore_role = ROLE_CONTROL_PLANE;
    lcore->state = RUNNING;

    /* Do All initialization here */
    sem_post(init_wait_sema);
}

static void 
data_path_thread_setup (lcore_config_t *lcore) {

    lcore->lcore_role = ROLE_DATA_PLANE;
    lcore->state = RUNNING;
}


int
lcore_init(void) {

    int count = 0;
    uint32_t lcore_id;
    lcore_config_t *lcore;
    sem_t init_wait_sema;

    sem_init(&init_wait_sema, 0, 0);

    for (lcore_id = 0; lcore_id < MAX_LCORE_SUPPORTED; lcore_id++) {

        lcore = &lcore_config[lcore_id];
        
        /* Detect the CPU of this lcore */
		if (eal_cpu_detected(lcore_id) == 0) {
			lcore->lcore_role = ROLE_OFF;
			lcore->core_index = -1;
			continue;
		}

        lcore->lcore_id = lcore_id;

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

        /* Open Communication Pipes to exchange info with main thread*/
        if (lcore_id != 0) {

            if (pipe(lcore->pipe_main2worker) < 0) {
                cprintf("Error: Failed to open pipe for lcore %d\n", lcore_id);
                exit(1);
            }

            if (pipe(lcore->pipe_worker2main) < 0) {
                cprintf("Error: Failed to open pipe for lcore %d\n", lcore_id);
                exit(1);
            }
        }
        
        if (lcore_id == 0) {
            control_plane_thread_setup(lcore, &init_wait_sema);
            sem_wait(&init_wait_sema);
            continue;
        }

        data_path_thread_setup(lcore);

        #if 0
            /* Create Data path threads now */
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            pthread_create(&lcore->thread_id, &attr, 
                    lcore_id == 0 ? controlplane_thread_function : data_path_thread_function, 
                    (void *)lcore_id);
            pthread_attr_destroy(&attr);

            /* Pin thread to CPU set*/
            pthread_setaffinity_np(lcore->thread_id, sizeof(cpu_set_t), &lcore->cpuset);
        #endif
    }

    /* number of lcore threads forked*/
    return count;
}
