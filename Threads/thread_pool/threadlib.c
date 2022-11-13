/*
 * =====================================================================================
 *
 *       Filename:  threadlib.c
 *
 *    Description: This file represents the thread library created over POSIX library 
 *
 *        Version:  1.0
 *        Created:  03/28/2021 07:14:35 AM
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
#include "../../gluethread/glthread.h"
#include "threadlib.h"
#include "../../BitOp/bitsop.h"

thread_t *
thread_create(thread_t *thread, char *name) {
    
    if (!thread) {
        thread = calloc (1, sizeof(thread_t));
    }

    strncpy(thread->name, name, sizeof(thread->name));
    thread->thread_created = false;
    thread->arg = NULL;
    thread->thread_fn = NULL;
	thread->flags = 0;
	thread->thread_pause_fn = 0;
	thread->pause_arg = 0;
	pthread_mutex_init(&thread->state_mutex, NULL);
	pthread_cond_init(&thread->cv, NULL);
	pthread_attr_init(&thread->attributes);
    return thread;
}

void
thread_run(thread_t *thread, void *(*thread_fn)(void *), void *arg) {

    thread->thread_fn = thread_fn;
    thread->arg = arg;
    thread->thread_created = true;
    thread->flags |=  THREAD_F_RUNNING;
    pthread_create(&thread->thread,
            &thread->attributes,
            thread_fn,
            arg);
}

void
thread_set_thread_attribute_joinable_or_detached(
                    thread_t *thread, bool joinable) {

    pthread_attr_setdetachstate(&thread->attributes,
            joinable ? PTHREAD_CREATE_JOINABLE :
            PTHREAD_CREATE_DETACHED);
}

/*
 * Thread pausing and resuming
 */

void
thread_set_pause_fn(thread_t *thread,
                    void *(*thread_pause_fn)(void *),
                    void *pause_arg) {

    thread->thread_pause_fn = thread_pause_fn;
    thread->pause_arg = pause_arg;
}

void
thread_pause(thread_t *thread) {

    pthread_mutex_lock(&thread->state_mutex);

    if (thread->flags & THREAD_F_RUNNING) {

        thread->flags |= THREAD_F_MARKED_FOR_PAUSE;
    }
    pthread_mutex_unlock(&thread->state_mutex);
}

void
thread_resume(thread_t *thread) {

    pthread_mutex_lock(&thread->state_mutex);

    if ((thread->flags & THREAD_F_PAUSED)) {
        pthread_cond_signal(&thread->cv);
    }
    pthread_mutex_unlock(&thread->state_mutex);
}

void
thread_test_and_pause(thread_t *thread) {

    pthread_mutex_lock(&thread->state_mutex);

    if (thread->flags & THREAD_F_MARKED_FOR_PAUSE) {

        thread->flags |= THREAD_F_PAUSED;

        thread->flags &=  ~THREAD_F_MARKED_FOR_PAUSE;
        thread->flags &=  ~THREAD_F_RUNNING;
        pthread_cond_wait(&thread->cv, &thread->state_mutex);
		thread->flags |= THREAD_F_RUNNING;
        thread->flags &= ~THREAD_F_PAUSED;
		(thread->thread_pause_fn)(thread->pause_arg);
        pthread_mutex_unlock(&thread->state_mutex);
    }
    else {
        pthread_mutex_unlock(&thread->state_mutex);
    }
}


void
thread_pool_init (thread_pool_t *th_pool ) {

    init_glthread(&th_pool->pool_head);
    pthread_mutex_init(&th_pool->mutex, NULL);
}

void
thread_pool_insert_new_thread (thread_pool_t *th_pool, thread_t *thread) {

    pthread_mutex_lock(&th_pool->mutex);

    assert (IS_GLTHREAD_LIST_EMPTY(&thread->wait_glue));
    assert(thread->thread_fn == NULL);

    glthread_add_next(&th_pool->pool_head,
            &thread->wait_glue);

    pthread_mutex_unlock(&th_pool->mutex);
}

thread_t *
thread_pool_get_thread (thread_pool_t *th_pool) {
    
    thread_t *thread = NULL;
    glthread_t *glthread = NULL;

    pthread_mutex_lock(&th_pool->mutex);
    glthread = dequeue_glthread_first(&th_pool->pool_head);
    if (!glthread) {
        pthread_mutex_unlock(&th_pool->mutex);
        return NULL;
    }
    thread = wait_glue_to_thread(glthread);
    pthread_mutex_unlock(&th_pool->mutex);
    return thread;
}


static void
thread_pool_run_thread (thread_t *thread) {

    assert (IS_GLTHREAD_LIST_EMPTY(&thread->wait_glue));

    if (!thread->thread_created) {
        thread_run (thread, thread->thread_fn, thread->arg);
    }
    else {
        /*  If the thread is already created, it means the thread is
         *  in blocked state as it has completed its previous task. So
         *  resume the thread execution again
         *                                   */
        pthread_cond_signal(&thread->cv);
    }
}


static void
thread_pool_thread_stage3_fn(thread_pool_t *th_pool,
        thread_t *thread) {

    pthread_mutex_lock(&th_pool->mutex);

    glthread_add_next (&th_pool->pool_head,
                       &thread->wait_glue);

    if (thread->semaphore) {

        sem_post(thread->semaphore);
    }

    /*  Rest in peace again in thread pool after completing the task*/
    pthread_cond_wait(&thread->cv, &th_pool->mutex);
    pthread_mutex_unlock(&th_pool->mutex);
}

static void *
thread_fn_execute_stage2_and_stage3 (void *arg)  {

    thread_execution_data_t *thread_execution_data =
        (thread_execution_data_t *)arg;

    while ( 1 ) {
        /*  Stage 2 : User defined function with user defined argument*/
        thread_execution_data->thread_stage2_fn (thread_execution_data->stage2_arg);
        /*   Stage 3 : Queue the thread in thread pool and block it*/
        thread_execution_data->thread_stage3_fn (
                thread_execution_data->thread_pool, thread_execution_data->thread);
    }
}

void
thread_pool_dispatch_thread (thread_pool_t *th_pool,     
                             void *(*thread_fn)(void *),
                             void *arg, bool block_caller) {

    /*  get the thread from the thread pool*/
    thread_t *thread = thread_pool_get_thread (th_pool);

    if (!thread) {
        thread = thread_create(0, "Dynamic");
        thread_pool_insert_new_thread(th_pool, thread);
    }

    if (block_caller && !thread->semaphore) {

        thread->semaphore = calloc(1, sizeof(sem_t));
        sem_init(thread->semaphore, 0, 0);
    }

    thread_execution_data_t *thread_execution_data =
        (thread_execution_data_t *)(thread->arg);

    if (thread_execution_data == NULL ) {
        /*  In this data structure, we would wrap up all the information
         *  which thread needs to execute stage 2 ans stage 3
         **/
        thread_execution_data = calloc (1, sizeof(thread_execution_data_t));
    }

    /*  Setup Stage 2 in which thread would do assigned task*/
    thread_execution_data->thread_stage2_fn = thread_fn;
    thread_execution_data->stage2_arg = arg;

    /*  Setup Stage 3 in which thread would park itself in thread pool */
    thread_execution_data->thread_stage3_fn = thread_pool_thread_stage3_fn;
    thread_execution_data->thread_pool = th_pool;
    thread_execution_data->thread = thread;

    /*  Assign the aggregate work to the thread to perform i.e. Stage 2 followed
     *  by stage 3 */
    thread->thread_fn = thread_fn_execute_stage2_and_stage3;
    thread->arg = (void *)thread_execution_data;

    /*  Fire the thread now */
    thread_pool_run_thread (thread);

    if (block_caller) {
        /*  Wait for the thread to finish the Stage 2 and Stage 3 work*/
        sem_wait(thread->semaphore);
        /*  Caller is notified , destory the semaphore */
        sem_destroy(thread->semaphore);
        free(thread->semaphore);
        thread->semaphore = NULL;
    }
}

