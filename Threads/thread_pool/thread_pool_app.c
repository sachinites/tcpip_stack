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


void *
even_thread_work_reverse(void *arg) {

    int i;
    for (i = 10; i > 0; i-=2) {
        printf("even = %d\n", i);
        sleep(1);
    }
}

void *
odd_thread_work_reverse(void *arg) {

    int i;
    for (i = 9; i > 0; i-=2) {
        printf("odd = %d\n", i);
        sleep(1);
    }
}


void *
even_thread_work(void *arg) {

    int i;
    for (i = 0; i < 10; i+=2) {
        printf("even = %d\n", i);
        sleep(1);
    }
}

void *
odd_thread_work(void *arg) {

    int i;
    for (i = 1; i < 10; i+=2) {
        printf("odd = %d\n", i);
        sleep(1);
    }
}

int
main(int argc, char **argv) {

    /*  Create and initialze a thread pool */
    thread_pool_t *th_pool = calloc(1, sizeof(thread_pool_t));
    thread_pool_init(th_pool);

    /*  Create two threads (not execution units, just thread_t data structures) */
    thread_t *thread1 = thread_create(0, "even_thread");
    thread_t *thread2 = thread_create(0, "odd_thread");

    /*  Insert both threads in thread pools*/
    thread_pool_insert_new_thread(th_pool, thread1);
    thread_pool_insert_new_thread(th_pool, thread2);

    thread_pool_dispatch_thread(th_pool, even_thread_work, 0, true);
    thread_pool_dispatch_thread(th_pool, odd_thread_work,  0, true);

    sleep(20);
    
    printf("Dispatching thread with new application work \n");
    thread_pool_dispatch_thread(th_pool, even_thread_work_reverse, 0, true);
    thread_pool_dispatch_thread(th_pool, odd_thread_work_reverse,  0, true);

    pthread_exit(0);
    return 0;
}

