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
#include "event_dispatcher.h"
#include "../LinuxMemoryManager/uapi_mm.h"

static bool debug = false;
void event_dispatcher_mem_init(); 

#define EVENT_DIS_PREEMPT_INTERVAL_IN_MSEC	500

void
event_dispatcher_init(event_dispatcher_t *ev_dis, const char *name){

	strncpy((char *)ev_dis->name, name, sizeof(ev_dis->name) - 1);
	ev_dis->name[sizeof(ev_dis->name) - 1] = '0';

	pthread_mutex_init(&ev_dis->ev_dis_mutex, NULL);
	init_glthread(&ev_dis->task_array_head[TASK_PRIORITY_HIGH]);
	init_glthread(&ev_dis->task_array_head[TASK_PRIORITY_MEDIUM]);
	init_glthread(&ev_dis->task_array_head[TASK_PRIORITY_LOW]);

	ev_dis->pending_task_count = 0;
	
	ev_dis->ev_dis_state = EV_DIS_IDLE;

	pthread_cond_init(&ev_dis->ev_dis_cond_wait, NULL);
	ev_dis->thread = NULL;
	ev_dis->signal_sent = false;
	ev_dis->current_task = NULL;
}

static void
event_dispatcher_schedule_task(event_dispatcher_t *ev_dis, task_t *task){

	assert(IS_GLTHREAD_LIST_EMPTY(&task->glue));

	EV_DIS_LOCK(ev_dis);

	glthread_add_last(&ev_dis->task_array_head[task->priority], &task->glue);
		
	if(debug) printf("Task Added to Dispatcher's Queue of priority %u\n", task->priority);
	
	ev_dis->pending_task_count++;

	if (ev_dis->ev_dis_state == EV_DIS_IDLE &&
		ev_dis->signal_sent == false) {

		pthread_cond_signal(&ev_dis->ev_dis_cond_wait);
		ev_dis->signal_sent = true;
		if(debug) printf("signal sent to dispatcher\n");
		ev_dis->signal_sent_cnt++;
	}

	if (task->app_cond_var) {

		if(debug) printf("Syn Task Waiting to return\n");
		pthread_cond_wait(task->app_cond_var,
						  &ev_dis->ev_dis_mutex);
		EV_DIS_UNLOCK(ev_dis);
		if(debug) printf("Syn Task Returned\n");
		/* Task finished, free now */
		free(task->app_cond_var);
		XFREE(task);
	}
	else {
		EV_DIS_UNLOCK(ev_dis);
	}
}

static void
eve_dis_process_task_post_call(event_dispatcher_t *ev_dis, task_t *task){

	pkt_q_t *pkt_q;

	switch(task->task_type) {

		case TASK_ONE_SHOT:
			if(task->re_schedule == false){
				if(task->app_cond_var) {
					/* We will free the task when it will be
 					 * unlocked, dont free here */
					if(debug) printf("Dispatcher sent Signal Syn Task\n");
					pthread_cond_signal(task->app_cond_var);
				}
				else {
					XFREE(task);
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
				if(debug) printf("Queue Exhausted, will stop until pkt enqueue..\n");
				pthread_mutex_unlock(&pkt_q->q_mutex);
				return;
			}

			if(debug) printf("more pkts in Queue, will continue..\n");

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

	curr = dequeue_glthread_first(&ev_dis->task_array_head[TASK_PRIORITY_HIGH]);
	if (curr) return glue_to_task(curr);
	curr = dequeue_glthread_first(&ev_dis->task_array_head[TASK_PRIORITY_MEDIUM]);
	if (curr) return glue_to_task(curr);
	curr = dequeue_glthread_first(&ev_dis->task_array_head[TASK_PRIORITY_LOW]);
	if (curr) return glue_to_task(curr);
	return NULL;
}

static void *
event_dispatcher_thread(void *arg) {

	task_t *task;
	event_dispatcher_t *ev_dis = (event_dispatcher_t *)arg;

	if (debug) {
		printf("Dispatcher Thread started\n");
	}

	initscr();

	while (1) {

		EV_DIS_LOCK(ev_dis);

		while (!(task = event_dispatcher_get_next_task_to_run(ev_dis))) {
			
			ev_dis->ev_dis_state = EV_DIS_IDLE;
			
			if (debug) {
				printf("No Task to run, EVE DIS %p moved to IDLE STATE\n", ev_dis);
			}
			
			ev_dis->signal_sent = false;
			
			pthread_cond_wait(&ev_dis->ev_dis_cond_wait,
							  &ev_dis->ev_dis_mutex);

			ev_dis->signal_recv_cnt++;

			if (debug) {
				printf("Eve Dis recvd Signal # %u, woken up\n",
					   ev_dis->signal_recv_cnt);
			}

		} // inner while loop

		ev_dis->pending_task_count--;
		ev_dis->current_task = task;

		if (ev_dis->ev_dis_state != EV_DIS_TASK_FIN_WAIT) {

			ev_dis->ev_dis_state = EV_DIS_TASK_FIN_WAIT;

			if (debug)
				printf("EVE DIS moved to EV_DIS_TASK_FIN_WAIT, "
					   "dispatching the task\n");
		}

		EV_DIS_UNLOCK(ev_dis);

		if (debug) {
			printf("invoking the task\n");
		}

		gettimeofday(&ev_dis->current_task_start_time, NULL);
		task->ev_cbk(ev_dis, task->data, task->data_size);
		task->no_of_invocations++;
		ev_dis->n_task_exec++;

		if (debug) {
			printf("Job execution finished\n");
		}

		eve_dis_process_task_post_call(ev_dis, task);
		ev_dis->current_task = NULL;
	} // outer while ends
	return 0;
}

static task_t *
create_new_task(void *arg,
				uint32_t arg_size,
				event_cbk cbk){

	task_t *task = (task_t *)XCALLOC(0, 1, task_t);
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
event_dispatcher_run(event_dispatcher_t *ev_dis){

	pthread_attr_t attr;
	pthread_t *event_dis_thread;
	
	event_dis_thread = (pthread_t *)calloc(1, sizeof(pthread_t));
	ev_dis->thread = event_dis_thread;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(event_dis_thread, &attr,
					event_dispatcher_thread,
					ev_dis);
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
	event_dispatcher_schedule_task(ev_dis, task);
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
	event_dispatcher_schedule_task(ev_dis, task);
	return task;								
}

void
task_cancel_job(event_dispatcher_t *ev_dis, task_t *task){

	/* Dont kill yourself while you are still executing
	 * and you are one SHOT */
	if(ev_dis->current_task->task_type == TASK_ONE_SHOT &&
		ev_dis->current_task == task) {
		assert(0);
	}
	
	if (task->task_type == TASK_PKT_Q_JOB) {

		pkt_q_t *pkt_q = (pkt_q_t *)(task->data);

	 	pthread_mutex_lock(&pkt_q->q_mutex);
		delete_glthread_list(&pkt_q->q_head);
	 	pthread_mutex_unlock(&pkt_q->q_mutex);
		
		EV_DIS_LOCK(ev_dis);
		remove_glthread(&pkt_q->glue);
		remove_glthread(&task->glue);
		XFREE(task);
		EV_DIS_UNLOCK(ev_dis);
	}
	else if (task->task_type == TASK_ONE_SHOT ||
			  task->task_type == TASK_BG ) {
		EV_DIS_LOCK(ev_dis);
		remove_glthread(&task->glue);
		EV_DIS_UNLOCK(ev_dis);
		XFREE(task);	
	}
}

typedef struct pkt_{

	char *pkt;
	uint32_t pkt_size;
	glthread_t glue;
} pkt_t;
GLTHREAD_TO_STRUCT(glue_to_pkt, pkt_t, glue);

static pkt_t *
task_get_new_pkt(char *pkt, uint32_t pkt_size){

	pkt_t *_pkt = (pkt_t *)XCALLOC(0, 1, pkt_t);
	_pkt->pkt = pkt;
	_pkt->pkt_size = pkt_size;
	init_glthread(&_pkt->glue);
	return _pkt;
}

char *
task_get_next_pkt(event_dispatcher_t *ev_dis, uint32_t *pkt_size){

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
	XFREE(pkt);
	return actual_pkt;
}


bool
pkt_q_enqueue (event_dispatcher_t *ev_dis,
			  pkt_q_t *pkt_q,
			  char *_pkt, uint32_t pkt_size){
	
	pthread_mutex_lock(&pkt_q->q_mutex);

	if (pkt_q->pkt_count > PKT_Q_MAX_QUEUE_SIZE) {
		pkt_q->drop_count++;
		pthread_mutex_unlock(&pkt_q->q_mutex);
		return false;
	}

	pkt_t *pkt = task_get_new_pkt(_pkt, pkt_size);
	
	if (debug) printf("%s() ... \n", __FUNCTION__);
	
	glthread_add_next(&pkt_q->q_head, &pkt->glue);
	pkt_q->pkt_count++;

	EV_DIS_LOCK(ev_dis);

	if ( !IS_GLTHREAD_LIST_EMPTY(&pkt_q->task->glue)) {
		EV_DIS_UNLOCK(ev_dis);
		pthread_mutex_unlock(&pkt_q->q_mutex);
		return true;
	}

	EV_DIS_UNLOCK(ev_dis);
	if (debug) printf("%s() calling event_dispatcher_schedule_task()\n",
			__FUNCTION__);
	event_dispatcher_schedule_task(ev_dis, pkt_q->task);
	pthread_mutex_unlock(&pkt_q->q_mutex);
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
		if (debug) printf ("ED should suspend, diff = %llu\n", diff);
		return true;
	}
	return false;
}

void
event_dispatcher_mem_init() {

	MM_REG_STRUCT(0, task_t);
	MM_REG_STRUCT(0, pkt_t);
}
