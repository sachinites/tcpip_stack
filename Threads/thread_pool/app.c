/*
 * =====================================================================================
 *
 *       Filename:  app.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  03/29/2021 07:10:58 AM
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
#include "../../gluethread/glthread.h"
#include "threadlib.h"

void *pause_sample_fn(void *arg) {
	
	printf("%s invoked\n", __FUNCTION__);
	return NULL;
}

void *
write_into_file_fn(void *arg) {

	thread_t *thread = (thread_t *)arg;
	
	while(1){
		printf("Thread writing into file\n");
		sleep(1);
		thread_test_and_pause(thread);
	}
	return NULL;
}

int
main(int argc, char **argv) {

	thread_t *console_writer_thread = thread_create(0, "file-writer");
	
	thread_set_thread_attribute_joinable_or_detached(console_writer_thread, false);
	
	thread_set_pause_fn(console_writer_thread, pause_sample_fn, (void *)console_writer_thread);
	
	thread_run(console_writer_thread, write_into_file_fn, console_writer_thread);

	int choice;
	
	do {
		printf("1. pause\n");
		printf("2. resume\n");

		printf("Enter choice: ");
		scanf("%d", &choice);
		
		switch(choice) {
			case 1:
				thread_pause(console_writer_thread);
				break;
			case 2:
				thread_resume(console_writer_thread);
				break;
			default:
				break;
		}
	} while(1);
	
	return 0;
}
