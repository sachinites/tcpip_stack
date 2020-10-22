/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description: This file demonstrates the use of Event Dispatcher 
 *
 *        Version:  1.0
 *        Created:  10/20/2020 02:14:05 PM
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
#include <unistd.h>
#include "event_dispatcher.h"

void
compute_square2(void *arg, uint32_t arg_size){

	int *a = (int *)arg;
	printf("Square of %d = %d\n", *a, (*a) * (*a));	
	task_t *task = eve_dis_get_current_task();
	printf("current task = %p\n", task);
	//sleep(2);
}

void
compute_square(void *arg, uint32_t arg_size){

	int *a = (int *)arg;
	printf("Square of %d = %d\n", *a, (*a) * (*a));

	task_t *task = eve_dis_get_current_task();
	printf("current task = %p\n", task);
	
	a = calloc(1, sizeof(int));
	*a = 10;
	//task_t *task_2 	= create_new_task((void *)a, sizeof(*a), compute_square2);
	task_t *task_2 = task_create_new_job(a, compute_square2, TASK_ONE_SHOT);
	a = calloc(1, sizeof(int));
	*a = 20;
	//task_t *task_3 	= create_new_task((void *)a, sizeof(*a), compute_square2);
	task_create_new_job(a, compute_square2, TASK_ONE_SHOT);
	//event_dispatcher_schedule_task(task_2); 
	//event_dispatcher_schedule_task(task_3);
	//sleep(5);
}

int
main(int argc, char **argv){

	event_dispatcher_init();
	event_dispatcher_run();
	//sleep(1);

	int *a = calloc(1, sizeof(int));
	*a = 5;
	task_t *task_1 	= task_create_new_job((void *)a, compute_square, TASK_ONE_SHOT);

	a = calloc(1, sizeof(int));
	*a = 6;
	task_t *task_2 	= task_create_new_job((void *)a, compute_square, TASK_ONE_SHOT);

	a = calloc(1, sizeof(int));
	*a = 9;
	task_t *task_3 	= task_create_new_job((void *)a, compute_square, TASK_ONE_SHOT);

	pause(); 
	return 0;
}




