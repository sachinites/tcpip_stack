/*
 * =====================================================================================
 *
 *       Filename:  timerExample.c
 *
 *    Description: This file demonstrates the use of POSIX Timer routines
 *
 *        Version:  1.0
 *        Created:  10/12/2020 11:25:06 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <assert.h>
#include <errno.h>
#include "timerlib.h"

unsigned long
timespec_to_millisec(
    struct timespec *time){

    unsigned long milli_sec = 0;

    milli_sec = time->tv_sec * 1000;
    milli_sec += time->tv_nsec / 1000000;
    return milli_sec;
}

void
timer_fill_itimerspec(struct timespec *ts,
					  unsigned long msec) {

	memset(ts, 0, sizeof(struct timespec));

	if(!msec) return;

	unsigned long sec = msec/1000;
	ts->tv_sec = sec;

	unsigned long remaining_msec = msec % 1000;
	
	ts->tv_nsec = remaining_msec * (1000000);
}

static void
timer_callback_wrapper(union sigval arg){

	Timer_t *timer = (Timer_t *)(arg.sival_ptr);

	timer->invocation_counter++;

	if(timer->thresdhold && 
		(timer->invocation_counter > timer->thresdhold)){
		cancel_timer(timer);
		return;
	}

	(timer->cb)(timer, timer->user_arg);
	
	if(timer->exponential_backoff){

		assert(timer->exp_back_off_time);	
		reschedule_timer(timer, 
			timer->exp_back_off_time *= 2, 0);	
	}
	else if(timer->timer_state == TIMER_RESUMED){
		
		reschedule_timer(timer,
			timer->exp_timer, timer->sec_exp_timer);
	}
}


/*  Returns NULL in timer creation fails, else
 *  return a pointer to Timer object*/
Timer_t*
setup_timer(
    void (*timer_cb)(Timer_t*, void *), /*  Timer Callback with user data*/
    unsigned long exp_timer,         	/*  First expiration time interval in msec */
    unsigned long sec_exp_timer,        /*  Subsequent expiration time interval in msec */
	uint32_t threshold,					/*  Max no of expirations, 0 for infinite*/
    void *user_arg,                  	/*  Arg to timer callback */
	bool exponential_backoff){			/*  Is Timer Exp backoff*/

	Timer_t *timer = (Timer_t *)calloc(1, sizeof(Timer_t));	

	timer->user_arg = user_arg;
	timer->exp_timer = exp_timer;
	timer->sec_exp_timer = sec_exp_timer;
	timer->cb = timer_cb;
	timer->thresdhold = threshold;
	timer_set_state(timer, TIMER_INIT);
	timer->exponential_backoff = exponential_backoff;

	/* Sanity checks */ 
	assert(timer->cb);	/* Mandatory */
	

	struct sigevent evp;
	memset(&evp, 0, sizeof(struct sigevent));

	evp.sigev_value.sival_ptr = (void *)(timer);
	evp.sigev_notify = SIGEV_THREAD;
	evp.sigev_notify_function = timer_callback_wrapper;

	int rc = timer_create (CLOCK_REALTIME,
							&evp, &timer->posix_timer);

	assert(rc >= 0);

	timer_fill_itimerspec(&timer->ts.it_value, timer->exp_timer);

	if(!timer->exponential_backoff){
		timer_fill_itimerspec(&timer->ts.it_interval, timer->sec_exp_timer);
		timer->exp_back_off_time = 0;
	}
	else{
		timer->exp_back_off_time = timespec_to_millisec(&timer->ts.it_value); 
		timer_fill_itimerspec(&timer->ts.it_interval, 0);
	}
	return timer;
}

void
resurrect_timer(Timer_t *timer){

	int rc;
	rc = timer_settime(timer->posix_timer, 0, &timer->ts, NULL);
	assert(rc >= 0);
}

void
start_timer(Timer_t *timer){

	resurrect_timer(timer);
	timer_set_state(timer, TIMER_RUNNING);
}

void
delete_timer(Timer_t *timer){

	int rc;
	rc = timer_delete(timer->posix_timer);
	assert(rc >= 0);
	timer->user_arg = NULL; /* User arg need to be freed by Appln */
	timer_set_state(timer, TIMER_DELETED);
}

void
cancel_timer(Timer_t *timer){

	TIMER_STATE_T timer_curr_state;

	timer_curr_state = timer_get_current_state(timer);

	if(timer_curr_state == TIMER_INIT || 
		timer_curr_state == TIMER_DELETED) {
		
		return; /*  No-Operation */
	}

	/* Only Paused or running timer can be cancelled */
	timer_fill_itimerspec(&timer->ts.it_value, 0);
	timer_fill_itimerspec(&timer->ts.it_interval, 0);
	timer->time_remaining = 0;
	timer->invocation_counter = 0;
	resurrect_timer(timer);
	timer_set_state(timer, TIMER_CANCELLED);
}


void
pause_timer(Timer_t *timer){

	if ( timer_get_current_state(timer) == TIMER_PAUSED)
		return;

	timer->time_remaining = 
		timer_get_time_remaining_in_mill_sec(timer);
	
	timer_fill_itimerspec(&timer->ts.it_value, 0);
	timer_fill_itimerspec(&timer->ts.it_interval, 0);
	
    resurrect_timer(timer);
	
	timer_set_state(timer, TIMER_PAUSED);
}


void
resume_timer(Timer_t *timer){

	assert(timer_get_current_state(timer) == TIMER_PAUSED);

	if (timer->time_remaining) {	
		timer_fill_itimerspec(&timer->ts.it_value, timer->time_remaining);
	}
	else {
		timer_fill_itimerspec(&timer->ts.it_value, timer->exp_timer);
	}

	timer_fill_itimerspec(&timer->ts.it_interval, timer->sec_exp_timer);

	if (timer->ts.it_value.tv_sec == 0 &&
		timer->ts.it_value.tv_nsec == 0) {
		assert(0);
	}
			
	timer->time_remaining	 = 0;
	resurrect_timer(timer);
	timer_set_state(timer, TIMER_RESUMED);
}

unsigned long
timer_get_time_remaining_in_mill_sec(Timer_t *timer){

	struct itimerspec remaining_time;

	switch(timer->timer_state){

		case TIMER_INIT:
			break;
		case TIMER_DELETED:
			return ~0;
		case TIMER_PAUSED:
			break;
		case TIMER_CANCELLED:
			return ~0;
		case TIMER_RUNNING:
			break;
		default : ;
	}

	memset(&remaining_time, 0, sizeof(struct itimerspec));

	timer_gettime(timer->posix_timer, &remaining_time);

	return timespec_to_millisec(&remaining_time.it_value);
}

void
restart_timer(Timer_t *timer){

	assert(timer->timer_state != TIMER_DELETED);

	cancel_timer(timer);

	timer_fill_itimerspec(&timer->ts.it_value, timer->exp_timer);

	if(!timer->exponential_backoff)
    timer_fill_itimerspec(&timer->ts.it_interval, timer->sec_exp_timer);
	else
	timer_fill_itimerspec(&timer->ts.it_interval, 0);

	timer->invocation_counter = 0;
	timer->time_remaining = 0;	
	timer->exp_back_off_time = timer->exp_timer;
	resurrect_timer(timer);
	timer_set_state(timer, TIMER_RUNNING);
}


void
reschedule_timer(Timer_t *timer,
				 unsigned long exp_ti,
				 unsigned long sec_exp_ti){

	uint32_t invocation_counter;
	TIMER_STATE_T timer_state;

	timer_state = timer_get_current_state(timer);

	if(timer_state == TIMER_DELETED) assert(0);
	
	invocation_counter = timer->invocation_counter;

	if(timer_state != TIMER_CANCELLED) {
		cancel_timer(timer);
	}

	timer->invocation_counter = invocation_counter;

	timer_fill_itimerspec(&timer->ts.it_value, exp_ti);

	if(!timer->exponential_backoff){
		timer_fill_itimerspec(&timer->ts.it_interval, sec_exp_ti);
	}
	else{
		timer_fill_itimerspec(&timer->ts.it_interval, 0);
		timer->exp_back_off_time = exp_ti;
	}

    timer->time_remaining = 0;
	resurrect_timer(timer);
	timer_set_state(timer, TIMER_RUNNING);
}

void
print_timer(Timer_t *timer){

	printf("Counter = %u, time remaining = %lu, state = %d\n",
		timer->invocation_counter,
		timer_get_time_remaining_in_mill_sec(timer),
		timer_get_current_state(timer));
}

bool
is_timer_running(Timer_t *timer){

	TIMER_STATE_T timer_state;

	timer_state = timer_get_current_state(timer);

	if(timer_state == TIMER_RUNNING ||
		timer_state == TIMER_RESUMED) {
		return true;
	}
	return false;
}

