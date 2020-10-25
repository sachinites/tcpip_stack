/*
 * =====================================================================================
 *
 *       Filename:  event_dispatcher.h
 *
 *    Description: This file defines the data structures for Event Dispatcher Design 
 *
 *        Version:  1.0
 *        Created:  10/20/2020 08:47:29 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#ifndef EVENT_DISPATCHER
#define EVENT_DISPATCHER

#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>
#include "../gluethread/glthread.h"

typedef struct event_dispatcher_ event_dispatcher_t;
typedef struct task_ task_t;
typedef struct pkt_q_ pkt_q_t;

typedef void (*event_cbk)(void *, uint32_t );

typedef enum {

	TASK_ONE_SHOT,
	TASK_PKT_Q_JOB,
	TASK_BG
} task_type_t;

struct task_{

	void *data;
	uint32_t data_size;
	event_cbk ev_cbk;
	uint32_t no_of_invocations;
	task_type_t task_type;
	bool re_schedule;
	pthread_cond_t *app_cond_var; /* For synchronous Schedules */
	glthread_t glue;
};
GLTHREAD_TO_STRUCT(glue_to_task,
	task_t, glue);

struct pkt_q_{

	glthread_t q_head;
	pthread_mutex_t q_mutex;
	task_t *task;
	glthread_t glue;
};
GLTHREAD_TO_STRUCT(glue_to_pkt_q,
	pkt_q_t, glue);

typedef enum {

	EV_DIS_IDLE,
	EV_DIS_TASK_FIN_WAIT,
} EV_DISPATCHER_STATE;

struct event_dispatcher_{

	pthread_mutex_t ev_dis_mutex;

	glthread_t task_array_head;	
	uint32_t pending_task_count;

	glthread_t pkt_queue_head;

	EV_DISPATCHER_STATE ev_dis_state;

	pthread_cond_t ev_dis_cond_wait;
	bool signal_sent;
	uint32_t signal_sent_cnt;
	uint32_t signal_recv_cnt;
	pthread_t *thread;	

	task_t *current_task;
};

#define EV_DIS_LOCK(ev_dis_ptr)		\
	(pthread_mutex_lock(&((ev_dis_ptr)->ev_dis_mutex)))

#define EV_DIS_UNLOCK(ev_dis_ptr)	\
	(pthread_mutex_unlock(&((ev_dis_ptr)->ev_dis_mutex)))

/* To be used by applications */
task_t *
eve_dis_get_current_task();

void
event_dispatcher_init();

void
event_dispatcher_run();

task_t *
task_create_new_job(
    void *data,
    event_cbk cbk,
	task_type_t task_type);

task_t *
task_create_new_job_synchronous(
    void *data,
    event_cbk cbk,
	task_type_t task_type);

void
task_cancel_job(task_t *task);

void
init_pkt_q(pkt_q_t *pkt_q, event_cbk cbk);

void
pkt_q_enqueue(pkt_q_t *pkt_q,
			  char *pkt, uint32_t pkt_size);

char *
task_get_next_pkt(uint32_t *pkt_size);

void
task_schedule_again(task_t *task);

#endif /* EVENT_DISPATCHER  */
