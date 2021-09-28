/*
 * =====================================================================================
 *
 *       Filename:  event_dispatcher.c
 *
 *    Description: This file defines the routine to imeplement Event Dispatcher
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
#include "event_dispatcher.h"
#include "../LinuxMemoryManager/uapi_mm.h"

static event_dispatcher_t ev_dis;
bool static debug = false;


void
event_dispatcher_init(){

	pthread_mutex_init(&ev_dis.ev_dis_mutex, NULL);
	init_glthread(&ev_dis.task_array_head);
	ev_dis.pending_task_count = 0;
	
	ev_dis.ev_dis_state = EV_DIS_IDLE;

	pthread_cond_init(&ev_dis.ev_dis_cond_wait, NULL);
	ev_dis.thread = NULL;
	ev_dis.signal_sent = false;
	ev_dis.current_task = NULL;
}

static void
event_dispatcher_schedule_task(task_t *task){

	/* TASK_PKT_Q_JOB could be scheduled again because of
 	 * enque-ing of more pkts via external thread while
 	 * the dispatcher mmay have removed it already from
 	 * its task_array_head Queue for processing.
 	 */
	if (task->task_type == TASK_PKT_Q_JOB && 
		!IS_GLTHREAD_LIST_EMPTY(&task->glue)) {
		return;
	}

	assert(IS_GLTHREAD_LIST_EMPTY(&task->glue));

	EV_DIS_LOCK(&ev_dis);

	glthread_add_last(&ev_dis.task_array_head, &task->glue);
	
	if(debug) printf("Task Added to Dispatcher's Queue\n");
	
	ev_dis.pending_task_count++;

	if (ev_dis.ev_dis_state == EV_DIS_IDLE &&
		ev_dis.signal_sent == false) {

		pthread_cond_signal(&ev_dis.ev_dis_cond_wait);
		ev_dis.signal_sent = true;
		if(debug) printf("signal sent to dispatcher\n");
		ev_dis.signal_sent_cnt++;
	}

	if (task->app_cond_var) {

		if(debug) printf("Syn Task Waiting to return\n");
		pthread_cond_wait(task->app_cond_var,
						  &ev_dis.ev_dis_mutex);
		EV_DIS_UNLOCK(&ev_dis);
		if(debug) printf("Syn Task Returned\n");
		/* Task finished, free now */
		free(task->app_cond_var);
		XFREE(task);
	}
	else {
		EV_DIS_UNLOCK(&ev_dis);
	}
}

static void
eve_dis_process_task_post_call(task_t *task){

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
				event_dispatcher_schedule_task(task);
			}
			break;
	
		case TASK_BG:
			event_dispatcher_schedule_task(task);
			break;	

		case TASK_PKT_Q_JOB:	
			pkt_q = (pkt_q_t *)(task->data);
			pthread_mutex_lock(&pkt_q->q_mutex);
			
			if (IS_GLTHREAD_LIST_EMPTY(&pkt_q->q_head)) {
				if(debug) printf("Queue Exhausted, will stop untill pkt enqueue..\n");
				pthread_mutex_unlock(&pkt_q->q_mutex);
				return;
			}
			pthread_mutex_unlock(&pkt_q->q_mutex);
			if(debug) printf("more pkts in Queue, will continue..\n");
			event_dispatcher_schedule_task(task);
			break;

		default:
		;
	}
}

static task_t *
event_dispatcher_get_next_task_to_run(){

	glthread_t *curr;
	curr = dequeue_glthread_first(&ev_dis.task_array_head);
	if(!curr) return NULL;
	return glue_to_task(curr);
}

static void *
event_dispatcher_thread(void *arg) {

	task_t *task;

	EV_DIS_LOCK(&ev_dis);

	if(debug) printf("Dispatcher Thread started\n");

	while(1) {
		
		task = event_dispatcher_get_next_task_to_run();

		if(!task) {
			ev_dis.ev_dis_state = EV_DIS_IDLE;
			if(debug) printf("No Task to run, EVE DIS moved to IDLE STATE\n");
			ev_dis.signal_sent = false;
			pthread_cond_wait(&ev_dis.ev_dis_cond_wait,
					&ev_dis.ev_dis_mutex);
			ev_dis.signal_recv_cnt++;
			if(debug) printf("Eve Dis recvd Signal # %u, woken up\n",
					ev_dis.signal_recv_cnt);
		}
		else {
			ev_dis.pending_task_count--;
			ev_dis.current_task = task;
			
			if(ev_dis.ev_dis_state != EV_DIS_TASK_FIN_WAIT){
				ev_dis.ev_dis_state = EV_DIS_TASK_FIN_WAIT;
				if(debug) printf("EVE DIS moved to EV_DIS_TASK_FIN_WAIT, "
						"dispatching the task\n");
			}

			EV_DIS_UNLOCK(&ev_dis);

			if(debug) printf("invoking the task\n");

			task->ev_cbk(task->data, task->data_size);
			task->no_of_invocations++;
			if(debug) printf("Job execution finished\n");

			eve_dis_process_task_post_call(task);

			EV_DIS_LOCK(&ev_dis);
			ev_dis.current_task = NULL;
		}
	}
	return 0;
}

static task_t *
create_new_task(void *arg,
				uint32_t arg_size,
				event_cbk cbk){

	task_t *task = XCALLOC(0, 1, task_t);
	task->data = arg;
	task->data_size = arg_size;
	task->ev_cbk = cbk;
	task->task_type = TASK_ONE_SHOT; /* default */
	task->re_schedule = false;
	init_glthread(&task->glue);
	return task;
}

void
task_schedule_again(task_t *task){

	if(task == NULL) {
		task = eve_dis_get_current_task();
	}
	assert(task->task_type == TASK_ONE_SHOT);
	task->re_schedule = true;
}

void
event_dispatcher_run(){

	pthread_attr_t attr;
	pthread_t *event_dis_thread;
	
	event_dis_thread = calloc(1, sizeof(pthread_t));
	ev_dis.thread = event_dis_thread;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(event_dis_thread, &attr,
					event_dispatcher_thread,
					NULL);
}

task_t *
eve_dis_get_current_task(){

	return ev_dis.current_task;
}


task_t *
task_create_new_job(
	void *data,
	event_cbk cbk,
	task_type_t task_type) {

	task_t *task = create_new_task(data, 0, cbk);
	task->task_type = task_type;
	event_dispatcher_schedule_task(task);
	return task;								
}

task_t *
task_create_new_job_synchronous(
	void *data,
	event_cbk cbk,
	task_type_t task_type) {

	task_t *task = create_new_task(data, 0, cbk);
	task->task_type = task_type;
	task->app_cond_var = calloc(1, sizeof(pthread_cond_t));
	pthread_cond_init(task->app_cond_var, 0);
	event_dispatcher_schedule_task(task);
	return task;								
}

void
task_cancel_job(task_t *task){

	/* Dont kill yourself while you are still executing
	 * and you are one SHOT */
	if(ev_dis.current_task->task_type == TASK_ONE_SHOT &&
		ev_dis.current_task == task) {
		assert(0);
	}
	
	if (task->task_type == TASK_PKT_Q_JOB) {

		pkt_q_t *pkt_q = (pkt_q_t *)(task->data);

	 	pthread_mutex_lock(&pkt_q->q_mutex);
		delete_glthread_list(&pkt_q->q_head);
	 	pthread_mutex_unlock(&pkt_q->q_mutex);
		
		EV_DIS_LOCK(&ev_dis);
		remove_glthread(&pkt_q->glue);
		remove_glthread(&task->glue);
		XFREE(task);
		EV_DIS_UNLOCK(&ev_dis);
	}
	else if (task->task_type == TASK_ONE_SHOT ||
			  task->task_type == TASK_BG ) {
		EV_DIS_LOCK(&ev_dis);
		remove_glthread(&task->glue);
		EV_DIS_UNLOCK(&ev_dis);
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

	pkt_t *_pkt = calloc(1, sizeof(pkt_t));
	_pkt->pkt = pkt;
	_pkt->pkt_size = pkt_size;
	init_glthread(&_pkt->glue);
	return _pkt;
}

char *
task_get_next_pkt(uint32_t *pkt_size){

	pkt_t *pkt;
	task_t *task;
	char *actual_pkt;
	glthread_t *curr;

	task = eve_dis_get_current_task();

	pkt_q_t *pkt_q = (pkt_q_t *)(task->data);

	pthread_mutex_lock(&pkt_q->q_mutex);
	curr = dequeue_glthread_first(&pkt_q->q_head);
	if(debug) printf("%s() ...\n", __FUNCTION__);
	pthread_mutex_unlock(&pkt_q->q_mutex);

	if(!curr) return NULL;

	pkt = glue_to_pkt(curr);

	actual_pkt = pkt->pkt;
	*pkt_size = pkt->pkt_size;
	free(pkt);
	return actual_pkt;
}


void
pkt_q_enqueue(pkt_q_t *pkt_q,
			  char *_pkt, uint32_t pkt_size){

	pkt_t *pkt = task_get_new_pkt(_pkt, pkt_size);
	
	if (debug) printf("%s() ... \n", __FUNCTION__);

	pthread_mutex_lock(&pkt_q->q_mutex);	
	glthread_add_next(&pkt_q->q_head, &pkt->glue);
	pthread_mutex_unlock(&pkt_q->q_mutex);

	EV_DIS_LOCK(&ev_dis);
	/* Job is already scheduled to run */
	if (!IS_GLTHREAD_LIST_EMPTY(&pkt_q->task->glue)){
		EV_DIS_UNLOCK(&ev_dis);
		return;
	}
	EV_DIS_UNLOCK(&ev_dis);
	if (debug) printf("%s() calling event_dispatcher_schedule_task()\n",
			__FUNCTION__);
	event_dispatcher_schedule_task(pkt_q->task);	
}

void
init_pkt_q(pkt_q_t *pkt_q, event_cbk cbk){

	init_glthread(&pkt_q->q_head);
	pthread_mutex_init(&pkt_q->q_mutex, NULL);
	pkt_q->task = create_new_task((void *)pkt_q,
								  sizeof(*pkt_q),
								  cbk);
	pkt_q->task->task_type = TASK_PKT_Q_JOB;
	init_glthread(&pkt_q->glue);
	glthread_add_next(&ev_dis.pkt_queue_head, &pkt_q->glue);
}

void
event_dispatcher_mem_init() {

	MM_REG_STRUCT(0, task_t);
}