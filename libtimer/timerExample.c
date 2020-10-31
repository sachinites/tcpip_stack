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

#include <signal.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

/* Example */

typedef struct pair_{

	int a;
	int b;
} pair_t;

pair_t pair = { 10, 20 };

/* Define the structure which will be passed as an
 * argument to the timer callback function, We do this
 * to have more control over the timer*/
typedef struct timer_user_arg_{

	void *user_arg;
	size_t user_arg_size;
	timer_t *timer;
	uint32_t counter;
} timer_user_arg_t;

typedef struct timer_user_arg_ Timer_t;

unsigned long
get_time_remaining_in_mill_sec(
	struct timespec *time){

	unsigned long milli_sec = 0;

	milli_sec = time->tv_sec * 1000;
	milli_sec += time->tv_nsec / 1000000;
	return milli_sec;
}

/* The Timer callback function which will be called every
 * time the timer expires. The signature of the function would be :
 * void <fn-name>(union sigval)
 * */
void
timer_callback(union sigval arg){

	/* Extract the user data structure*/
	timer_user_arg_t *timer_user_arg = 
		(timer_user_arg_t *) (arg.sival_ptr);

	pair_t *pair = (pair_t *)(timer_user_arg->user_arg);
	/* 
 	 * Timer is also passed as an argumeent to the timer
 	 * handler routine so that we can change the properties
 	 * of the timer from within the handler itself 
 	 * */
	timer_t *timer = timer_user_arg->timer;
	
	/* Get remaining time in next timer expiry */
	struct itimerspec remaining_time;
	memset(&remaining_time, 0, sizeof(struct itimerspec));

	int rc = timer_gettime(*timer, &remaining_time);

	printf("Timer = %p, Expiry Remaining time = %ld msec,"
		   " pair : [%d, %d], invocation no = %u, overrun = %d\n",
		   timer, get_time_remaining_in_mill_sec(&remaining_time.it_value),
		   pair->a, pair->b, timer_user_arg->counter,
		   timer_getoverrun(*timer));
	
	timer_user_arg->counter++;

	/* Let us kill the timer when it is invoked for 10 times */
	if(timer_user_arg->counter == 10){
		
		rc = timer_delete(*timer); /* Now timer wont fire 11th time */

		if(rc < 0) {

			printf("Error in Timer Deletion, errno = %d\n", errno);
			exit(0);
		}
		/* Free up all the memory/resources */
		free(timer_user_arg->timer);
		free(timer_user_arg);
		return;
	}
}

void
timer_demo(){

	int ret;
	timer_t *timer;
	struct sigevent evp;

	/* You can take it as a local variable if you
 	 * wish, in that case we will not free it in
 	 * timer handler fn */
	timer = calloc(1, sizeof(timer_t));

	/* evp variable is used to setup timer properties*/
	memset(&evp, 0, sizeof(struct sigevent));
	
	/* Fill the the user defined data structure.
 	 * When timer expires, this will be passed as
 	 * argument to the timer fn handler */
	timer_user_arg_t *timer_user_arg =
		calloc(1, sizeof(timer_user_arg_t));
	timer_user_arg->user_arg = (void *)&pair;
	timer_user_arg->user_arg_size = sizeof(pair_t);
	timer_user_arg->timer = timer;
	timer_user_arg->counter = 0;

	evp.sigev_value.sival_ptr = (void *)timer_user_arg;

	/* On timer Expiry, We want kernel to launch the
 	 * timer handler routine in a separate thread context */
	evp.sigev_notify = SIGEV_THREAD;
	
	/* Register the timer hander routine. This routine shall
 	 * be invoked when timer expires*/
	evp.sigev_notify_function = timer_callback; 

	/* Create a timer. It is just a timer initialization, Timer
 	 * is not fired (Alarmed)  */
	ret = timer_create (CLOCK_REALTIME,
						&evp,
						timer);

	if ( ret < 0) {
		
		printf("Timer Creation failed, errno = %d\n", errno);
		exit(0);
	}

	/* Let us say, I want to start the timer after 5 seconds from now
 	 * (now =  say, t = 0) and once the 5 seconds elapsed, i 
 	 * want the timer to keep firing after every 2 seconds repeatedly.
 	 * It simply mean that - if i start the timer as time t = 0, then
 	 * timer handler routine (timer_callback) shall be called at t = 5,
 	 * t = 7, t = 9 ... so on*/

	/* Let us setup the time intervals */

	struct itimerspec ts;

	/* I want the timer to fire for the first time after 5 seconds
 	 * and 0 nano seconds*/
	ts.it_value.tv_sec = 5;
	ts.it_value.tv_nsec = 0;

	/* After the timer has fired for the first time, i want the timer
 	 * to repeatedly fire after every 2 sec and 0 nano sec */
	ts.it_interval.tv_sec = 2;
	ts.it_interval.tv_nsec = 0;

	/* Now start the timer*/
	ret = timer_settime (*timer,
						 0,
						 &ts,
						 NULL);

	if ( ret < 0) {
		
		printf("Timer Start failed, errno = %d\n", errno);
		exit(0);
	}
}

/* Returns NULL in timer creation fails, else
 * return a pointer to Timer object*/
Timer_t*
setup_timer(
	void (*)(void *, size_t),	/* Timer Callback */
	unsigned long long,			/* First expiration time interval in msec */
	bool,						/* true if timer is repeatable, false for one-shot */
	unsigned long long,			/* Subsequent expiration time interval in msec */
	void *arg,					/* Arg to timer callback */
	size_t arg_size);			/* Arg memory size */


int
main(int argc, char **argv){

	timer_demo();
	pause();
	return 0;
}
