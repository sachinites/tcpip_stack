/*
 * =====================================================================================
 *
 *       Filename:  event_dispatcher.c
 *
 *    Description: This file defines the routine to implement Event Dispatcher
 *
 *        Version:  1.0
 *        Created:  10/20/2020 09:01:49 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include <unistd.h>
#include <ncurses.h>
#include <sched.h>
#include <time.h>
#include "event_dispatcher.h"
#include "../../tcp_ip_trace.h"
#include "../Tracer/tracer.h"
#include "../LinuxMemoryManager/uapi_mm.h"

tracer_t *sched_tracer = NULL; 

/*
 * Get the highest numbered CPU core (typically high-performance cores)
 * Returns the CPU core number to pin to, or -1 if unable to determine
 */
static int
event_dispatcher_get_high_perf_core(void) {
	int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	
	if (num_cpus <= 0) {
		fprintf(stderr, "Warning: Unable to determine number of CPUs\n");
		return -1;
	}
	
	/* Return the highest numbered CPU (typically high-performance core) */
	return num_cpus - 1;
}

/*
 * Pin the current thread to a specific CPU core
 * Returns 0 on success, -1 on failure
 */
static int
event_dispatcher_pin_thread_to_core(pthread_t thread, int core_id) {

	cpu_set_t cpuset;
	
	if (core_id < 0) return 0;
	
	CPU_ZERO(&cpuset);
	CPU_SET(core_id, &cpuset);
	
	int rc = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
	if (rc != 0) {
		fprintf(stderr, "Error: Failed to pin thread to core %d (errno=%d)\n", 
				core_id, rc);
		return -1;
	}
	
	tracer (sched_tracer, DSCHED, "Event Dispatcher: Thread pinned to CPU core %d\n", core_id);
	return 0;
} 

#define EVENT_DIS_PREEMPT_INTERVAL_IN_MSEC	500

void
event_dispatcher_init(event_dispatcher_t *ev_dis, const char *name){

	strncpy((char *)ev_dis->name, name, sizeof(ev_dis->name) - 1);
	ev_dis->name[sizeof(ev_dis->name) - 1] = '\0';
	pthread_mutex_init(&ev_dis->ev_dis_mutex, NULL);
	init_glthread(&ev_dis->task_array_head[TASK_PRIORITY_CRITICAL]);
	init_glthread(&ev_dis->task_array_head[TASK_PRIORITY_HIGH]);
	init_glthread(&ev_dis->task_array_head[TASK_PRIORITY_MEDIUM]);
	init_glthread(&ev_dis->task_array_head[TASK_PRIORITY_LOW_MEDIUM]);
	init_glthread(&ev_dis->task_array_head[TASK_PRIORITY_LOW]);
	init_glthread(&ev_dis->task_array_head[TASK_PRIORITY_VERY_LOW]);
	ev_dis->pending_task_count = 0;
	ev_dis->ev_dis_state = EV_DIS_IDLE;
	pthread_cond_init(&ev_dis->ev_dis_cond_wait, NULL);
	ev_dis->thread = NULL;
	ev_dis->signal_sent = false;
	ev_dis->current_task = NULL;
}

static bool
event_dispatcher_schedule_task(event_dispatcher_t *ev_dis, task_t *task){

	void *ptr = (void *) (ev_dis->app_data );

	EV_DIS_LOCK(ev_dis);

	if (task->priority < TASK_PRIORITY_FIRST ||
		task->priority >= TASK_PRIORITY_MAX) {
			tracer (sched_tracer, DERR,
			"event_dispatcher: invalid task priority %u (max %u), task=%p\n",
			(unsigned)task->priority,
			(unsigned)TASK_PRIORITY_MAX, (void *)task);
		EV_DIS_UNLOCK(ev_dis);
		assert(0);
	}

	if (!IS_GLTHREAD_LIST_EMPTY(&task->glue)) {
		/* Normal dedup: pkt_q tasks and BG tasks may already be queued.
		 * For a freshly created one-shot task this should never happen;
		 * catch that case with an assert so we can identify the caller. */
		if (task->task_type == TASK_ONE_SHOT) {
			tracer (sched_tracer, DERR,
				"event_dispatcher: BUG - ONE_SHOT task %p (cbk=%p) already "
				"linked (left=%p right=%p) -- task not enqueued\n",
				(void *)task, (void *)task->ev_cbk,
				(void *)task->glue.left, (void *)task->glue.right);
		}
		EV_DIS_UNLOCK(ev_dis);
		return false;
	}

	glthread_add_last(&ev_dis->task_array_head[task->priority], &task->glue);
	assert (!IS_GLTHREAD_LIST_EMPTY (&task->glue));

	tracer (sched_tracer, DSCHED, 
		"%p : Task Added to Dispatcher's Queue of priority %u\n", ptr, task->priority);
	
	ev_dis->pending_task_count++;

	pthread_cond_signal(&ev_dis->ev_dis_cond_wait);
	ev_dis->signal_sent = true;
	ev_dis->signal_sent_cnt++;
	tracer (sched_tracer, DSCHED_DET, "%p : signal sent to dispatcher\n", ptr);

	if (task->app_cond_var) {

		tracer (sched_tracer, DSCHED_DET, "%p : Syn Task Waiting to return\n", ptr);
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 10;
		pthread_cond_timedwait(task->app_cond_var,
						  &ev_dis->ev_dis_mutex, &ts);
		EV_DIS_UNLOCK(ev_dis);
		tracer (sched_tracer, DSCHED_DET, "%p : Syn Task Returned\n", ptr);
		/* Task finished, free now */
		free(task->app_cond_var);
		free(task);
		return true;
	}

	assert (!IS_GLTHREAD_LIST_EMPTY (&task->glue));
	EV_DIS_UNLOCK(ev_dis);
	return true;
}

static void
eve_dis_process_task_post_call(event_dispatcher_t *ev_dis, task_t *task){

	pkt_q_t *pkt_q;
	
	void *ptr = (void *) (ev_dis->app_data );
	
	switch(task->task_type) {

		case TASK_ONE_SHOT:
			if(task->re_schedule == false){
				if(task->app_cond_var) {
					/* We will free the task when it will be
 					 * unlocked, dont free here */
					tracer (sched_tracer, DSCHED_DET, 
						"%p : Dispatcher sent Signal Syn Task\n", ptr);
					pthread_cond_signal(task->app_cond_var);
				}
				else {
					free(task);
				}
			}
			else{
				task->re_schedule = false;
				event_dispatcher_schedule_task(ev_dis, task);
			}
			break;
	
		case TASK_BG:
			event_dispatcher_schedule_task(ev_dis, task);
			break;	

		case TASK_PKT_Q_JOB:	
			pkt_q = (pkt_q_t *)(task->data);

			pthread_mutex_lock(&pkt_q->q_mutex);
			
			if (IS_GLTHREAD_LIST_EMPTY(&pkt_q->q_head)) {
				tracer (sched_tracer, DSCHED_DET, 
					"%p : Queue Exhausted, will stop until pkt enqueue..\n", ptr);
				pthread_mutex_unlock(&pkt_q->q_mutex);
				return;
			}

			tracer (sched_tracer, DSCHED_DET, 
				"%p : more pkts in Queue, will continue..\n", ptr);

			EV_DIS_LOCK(ev_dis);

			if (!IS_GLTHREAD_LIST_EMPTY(&task->glue)) {
				EV_DIS_UNLOCK(ev_dis);
				pthread_mutex_unlock(&pkt_q->q_mutex);
				break;
			}
			EV_DIS_UNLOCK(ev_dis);
			pthread_mutex_unlock(&pkt_q->q_mutex);
			event_dispatcher_schedule_task(ev_dis, task);
			break;
		default: 		;
	}
}

static task_t *
event_dispatcher_get_next_task_to_run(event_dispatcher_t *ev_dis){

	glthread_t *curr;
	curr = dequeue_glthread_first(&ev_dis->task_array_head[TASK_PRIORITY_CRITICAL]);
	if (curr) return glue_to_task(curr);
	curr = dequeue_glthread_first(&ev_dis->task_array_head[TASK_PRIORITY_HIGH]);
	if (curr) return glue_to_task(curr);
	curr = dequeue_glthread_first(&ev_dis->task_array_head[TASK_PRIORITY_MEDIUM]);
	if (curr) return glue_to_task(curr);
	curr = dequeue_glthread_first(&ev_dis->task_array_head[TASK_PRIORITY_LOW_MEDIUM]);
	if (curr) return glue_to_task(curr);
	curr = dequeue_glthread_first(&ev_dis->task_array_head[TASK_PRIORITY_LOW]);
	if (curr) return glue_to_task(curr);
	curr = dequeue_glthread_first(&ev_dis->task_array_head[TASK_PRIORITY_VERY_LOW]);
	if (curr) return glue_to_task(curr);	
	return NULL;
}

static void *
event_dispatcher_thread(void *arg) {

	task_t *task;
	event_dispatcher_t *ev_dis = (event_dispatcher_t *)arg;
	void *ptr = (void *)(ev_dis->app_data);

	while (1) {

		EV_DIS_LOCK(ev_dis);

		while (!(task = event_dispatcher_get_next_task_to_run(ev_dis))) {
			
			ev_dis->ev_dis_state = EV_DIS_IDLE;
			
			tracer (sched_tracer, DSCHED_DET, 
					"%p : No Task to run, EVE DIS %p moved to IDLE STATE\n", ptr, ev_dis);
			
			ev_dis->signal_sent = false;
			
			pthread_cond_wait(&ev_dis->ev_dis_cond_wait,
							  &ev_dis->ev_dis_mutex);

			ev_dis->signal_recv_cnt++;

			tracer (sched_tracer, DSCHED_DET, 
				"%p : Eve Dis recvd Signal # %u, woken up\n",
				ptr, ev_dis->signal_recv_cnt);
			

		} // inner while loop

		ev_dis->pending_task_count--;
		ev_dis->current_task = task;

		if (ev_dis->ev_dis_state != EV_DIS_TASK_FIN_WAIT) {

			ev_dis->ev_dis_state = EV_DIS_TASK_FIN_WAIT;

			tracer (sched_tracer, DSCHED_DET, "%p : EVE DIS moved to EV_DIS_TASK_FIN_WAIT, "
					   "dispatching the task\n", ptr);
		}

		EV_DIS_UNLOCK(ev_dis);

		tracer (sched_tracer, DSCHED_DET, "%p : invoking the task\n", ptr);
		

		gettimeofday(&ev_dis->current_task_start_time, NULL);
		task->ev_cbk(ev_dis, task->data, task->data_size);
		task->no_of_invocations++;
		ev_dis->n_task_exec++;

		tracer (sched_tracer, DSCHED_DET, "%p : Job execution finished\n", ptr);
	
		eve_dis_process_task_post_call(ev_dis, task);

		EV_DIS_LOCK(ev_dis);
		ev_dis->current_task = NULL;
		EV_DIS_UNLOCK(ev_dis);
	} // outer while ends
	return 0;
}

static task_t *
create_new_task(void *arg,
				uint32_t arg_size,
				event_cbk cbk){

	task_t *task = (task_t *)calloc(1, sizeof(task_t));
	task->data = arg;
	task->data_size = arg_size;
	task->ev_cbk = cbk;
	task->task_type = TASK_ONE_SHOT; /* default */
	task->re_schedule = false;
	task->priority = TASK_PRIORITY_MEDIUM;
	init_glthread(&task->glue);
	return task;
}

void
task_schedule_again(event_dispatcher_t *ev_dis, task_t *task){

	if(task == NULL) {
		task = eve_dis_get_current_task(ev_dis);
	}
	assert(task->task_type == TASK_ONE_SHOT);
	task->re_schedule = true;
}

void
event_dispatcher_run(event_dispatcher_t *ev_dis, bool pin_to_core, int core_id){

	pthread_attr_t attr;
	pthread_t *event_dis_thread;
	
	event_dis_thread = (pthread_t *)calloc(1, sizeof(pthread_t));
	ev_dis->thread = event_dis_thread;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(event_dis_thread, &attr,
					event_dispatcher_thread,
					ev_dis);
	
	/* Pin thread to high-performance core if requested */
	if (pin_to_core && core_id >= 0)
	{
		/* Small delay to ensure thread is running before pinning */
		usleep(1000);
	}

	pthread_attr_destroy(&attr);
}

task_t *
eve_dis_get_current_task(event_dispatcher_t *ev_dis){

	return ev_dis->current_task;
}


task_t *
task_create_new_job(
	event_dispatcher_t *ev_dis,
	void *data,
	event_cbk cbk,
	task_type_t task_type,
	task_priority_t priority) {

	task_t *task = create_new_task(data, 0, cbk);
	task->task_type = task_type;
	task->priority = priority;
	/* A freshly calloc'd task always has glue == {NULL,NULL}, so
	 * event_dispatcher_schedule_task must succeed.  If it doesn't,
	 * something has corrupted the task's memory; free and signal the bug. */
	if (!event_dispatcher_schedule_task(ev_dis, task)) {
		tracer (sched_tracer, DERR, 
			"event_dispatcher: task_create_new_job failed to schedule "
			"fresh task %p (cbk=%p) -- memory corruption?\n",
			(void *)task, (void *)cbk);
		free(task);
		return NULL;
	}

	return task;
}

task_t *
task_create_new_job_synchronous(
	event_dispatcher_t *ev_dis,
	void *data,
	event_cbk cbk,
	task_type_t task_type,
	task_priority_t priority) {

	task_t *task = create_new_task(data, 0, cbk);
	task->task_type = task_type;
	task->priority = priority;
	task->app_cond_var = (pthread_cond_t *)calloc(1, sizeof(pthread_cond_t));
	pthread_cond_init(task->app_cond_var, 0);
	if (!event_dispatcher_schedule_task(ev_dis, task)) {
		free(task->app_cond_var);
		free(task);
		return NULL;
	}
	return task;								
}

static void
event_dispatcher_cancel_queued_task(event_dispatcher_t *ev_dis, task_t *task){

	if (!IS_QUEUED_UP_IN_THREAD(&task->glue)) {
		return;
	}

	remove_glthread(&task->glue);
	ev_dis->pending_task_count--;

	if (ev_dis->ev_dis_state == EV_DIS_IDLE &&
		ev_dis->signal_sent == false) {

		pthread_cond_signal(&ev_dis->ev_dis_cond_wait);
		ev_dis->signal_sent = true;
		ev_dis->signal_sent_cnt++;
	}
}

void
task_cancel_job(event_dispatcher_t *ev_dis, task_t *task){

	bool free_task = true;

	EV_DIS_LOCK(ev_dis);

	/* Dont kill yourself while you are still executing
	 * and you are one SHOT */
	if (ev_dis->current_task == task &&
		ev_dis->current_task->task_type == TASK_ONE_SHOT) {
		assert(0);
	}

	/* A running task is already dequeued; freeing it is unsafe. */
	if (ev_dis->current_task == task) {
		EV_DIS_UNLOCK(ev_dis);
		return;
	}

	if (task->app_cond_var) {
		pthread_cond_signal(task->app_cond_var);
		free_task = false;
	}

	if (task->task_type == TASK_PKT_Q_JOB) {

		pkt_q_t *pkt_q = (pkt_q_t *)(task->data);

		EV_DIS_UNLOCK(ev_dis);

		pthread_mutex_lock(&pkt_q->q_mutex);
		delete_glthread_list(&pkt_q->q_head);
		pkt_q->pkt_count = 0;
		pthread_mutex_unlock(&pkt_q->q_mutex);

		EV_DIS_LOCK(ev_dis);
		remove_glthread(&pkt_q->glue);
		event_dispatcher_cancel_queued_task(ev_dis, task);
		EV_DIS_UNLOCK(ev_dis);

		if (free_task) {
			free(task);
		}
		return;
	}

	if (task->task_type == TASK_ONE_SHOT ||
		task->task_type == TASK_BG) {

		event_dispatcher_cancel_queued_task(ev_dis, task);
		EV_DIS_UNLOCK(ev_dis);

		if (free_task) {
			free(task);
		}
		return;
	}

	EV_DIS_UNLOCK(ev_dis);
}

typedef struct pkt_{

	char *pkt;
	uint32_t pkt_size;
	glthread_t glue;
} pkt_t;
GLTHREAD_TO_STRUCT(glue_to_pkt, pkt_t, glue);

static pkt_t *
task_get_new_pkt(char *pkt, uint32_t pkt_size){

	pkt_t *_pkt = (pkt_t *)calloc(1, sizeof(pkt_t));
	_pkt->pkt = pkt;
	_pkt->pkt_size = pkt_size;
	init_glthread(&_pkt->glue);
	return _pkt;
}

char *
task_get_next_pkt (event_dispatcher_t *ev_dis, uint32_t *pkt_size){

	pkt_t *pkt;
	task_t *task;
	char *actual_pkt;
	glthread_t *curr;

	task = eve_dis_get_current_task(ev_dis);

	pkt_q_t *pkt_q = (pkt_q_t *)(task->data);

	pthread_mutex_lock(&pkt_q->q_mutex);
	curr = dequeue_glthread_first(&pkt_q->q_head);
	
	if(!curr) {
		pthread_mutex_unlock(&pkt_q->q_mutex);
		return NULL;
	}
	pkt_q->pkt_count--;
	pthread_mutex_unlock(&pkt_q->q_mutex);

	pkt = glue_to_pkt(curr);

	actual_pkt = pkt->pkt;
	*pkt_size = pkt->pkt_size;
	free(pkt);
	return actual_pkt;
}


bool
pkt_q_enqueue (event_dispatcher_t *ev_dis,
			  pkt_q_t *pkt_q,
			  char *_pkt, uint32_t pkt_size){
	
	void *ptr = (void *)(ev_dis->app_data);

	pthread_mutex_lock(&pkt_q->q_mutex);

	if (pkt_q->pkt_count > PKT_Q_MAX_QUEUE_SIZE) {
		pkt_q->drop_count++;
		pthread_mutex_unlock(&pkt_q->q_mutex);
		return false;
	}

	pkt_t *pkt = task_get_new_pkt(_pkt, pkt_size);
	
	glthread_add_last(&pkt_q->q_head, &pkt->glue);
	pkt_q->pkt_count++;

	pthread_mutex_unlock(&pkt_q->q_mutex);

	tracer (sched_tracer, DSCHED_DET, 
		"%p : %s() calling event_dispatcher_schedule_task()\n", ptr, __FUNCTION__);
		
	event_dispatcher_schedule_task(ev_dis, pkt_q->task);
	return true;
}

void
init_pkt_q(event_dispatcher_t *ev_dis, 
			pkt_q_t *pkt_q, event_cbk cbk){

	init_glthread(&pkt_q->q_head);
	pthread_mutex_init(&pkt_q->q_mutex, NULL);
	pkt_q->task = create_new_task((void *)pkt_q,
								  sizeof(*pkt_q),
								  cbk);
	pkt_q->task->task_type = TASK_PKT_Q_JOB;
	pkt_q->task->priority = TASK_PRIORITY_PKT_PROCESSING;
	init_glthread(&pkt_q->glue);
	glthread_add_next(&ev_dis->pkt_queue_head, &pkt_q->glue);
	pkt_q->ev_dis = ev_dis;
}

bool
event_dispatcher_should_suspend (event_dispatcher_t *ev_dis) {

	struct timeval *start_time = &ev_dis->current_task_start_time;
	struct timeval current_time;
	gettimeofday(&current_time, NULL);
	long long millisec_diff1 = (((long long)start_time->tv_sec)*1000) + (start_time->tv_usec/1000);
	long long millisec_diff2 = (((long long)current_time.tv_sec)*1000) + (current_time.tv_usec/1000);
	long long diff =  millisec_diff2 -  millisec_diff1;
	if (diff  >= EVENT_DIS_PREEMPT_INTERVAL_IN_MSEC) {
		tracer (sched_tracer, DSCHED_DET, "ED should suspend, diff = %llu\n", diff);
		return true;
	}
	return false;
}


int scheduler_task_queue(event_dispatcher_t *ev_dis) {

    tracer(sched_tracer, DSCHED_DET, "\n  Pending Task Queues:\n");
    glthread_t *curr;
    task_t *task;
    int count = 0;

    for (int pri = TASK_PRIORITY_FIRST; pri < TASK_PRIORITY_MAX; pri++) {

        if (IS_GLTHREAD_LIST_EMPTY(&ev_dis->task_array_head[pri])) continue;

        tracer(sched_tracer, DSCHED_DET, "    Priority (%d):\n", pri);

        int task_idx = 0;

        ITERATE_GLTHREAD_BEGIN(&ev_dis->task_array_head[pri], curr) {

            task = glue_to_task(curr);
            tracer(sched_tracer, DSCHED_DET, 
					"      [%d] task=%p cbk=%p data=%p data_size=%u type=%d "
                    "re_schedule=%s invocations=%u\n",
                    task_idx++, task, (void *)task->ev_cbk, task->data,
                    task->data_size, task->task_type,
                    task->re_schedule ? "true" : "false",
                    task->no_of_invocations);
            count++;

        } ITERATE_GLTHREAD_END(&ev_dis->task_array_head[pri], curr);
    }

    return count;
}