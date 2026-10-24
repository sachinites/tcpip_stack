/*
 * =====================================================================================
 *
 *       Filename:  LockLessEvDis_usage.cpp
 *
 *    Description:  Minimal sample showing how to use the lock-less Event
 *                  Dispatcher (LockLessEvDis).
 *
 *       Build   :  ./compile_ll.sh
 *       Run     :  ./ll_ev_dis_usage.exe
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <thread>

#include "LockLessEvDis.h"

/* Application payload carried through the pkt_q. */
typedef struct app_msg_ {
    int  id;
    char text[64];
} app_msg_t;

/* Frees leftover msgs if the pkt_q is torn down while packets remain.
 * NULL is also valid: then the application keeps ownership. */
static void
app_msg_free(void *p) {

    free(p);
}

/*
 * Callback runs on the dispatcher thread only. Drain this pkt_q until empty
 * (or until should_suspend asks you to yield for fairness).
 */
static void
pkt_q_callback(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg_size;
    ll_pkt_q_t *pkt_q = (ll_pkt_q_t *)arg;
    uint32_t pkt_size;
    char *raw;

    while ((raw = ll_task_get_next_pkt(ev_dis, &pkt_size)) != NULL) {

        app_msg_t *msg = (app_msg_t *)raw;
        printf("[dispatcher] pkt_q=%p pri=%d  msg id=%d text=\"%s\" (%u bytes)\n",
               (void *)pkt_q, pkt_q->priority, msg->id, msg->text, pkt_size);

        free(msg);   /* application frees each packet it consumes */

        /* Yield if this callback has run too long so other pkt_qs can run. */
        if (ll_event_dispatcher_should_suspend(ev_dis)) {
            printf("[dispatcher] yielding (preempt interval)\n");
            break;
        }
    }
}

/* Producer thread: any number of threads may enqueue concurrently. */
static void
producer(ll_event_dispatcher_t *ev_dis, ll_pkt_q_t *pkt_q,
         int start_id, int count) {

    for (int i = 0; i < count; i++) {
        app_msg_t *msg = (app_msg_t *)malloc(sizeof(*msg));
        if (!msg) continue;

        msg->id = start_id + i;
        snprintf(msg->text, sizeof(msg->text), "hello from producer, id=%d",
                 msg->id);

        /* On success ownership moves to the dispatcher / callback.
         * On failure the caller still owns the buffer. */
        if (!ll_pkt_q_enqueue(ev_dis, pkt_q, (char *)msg, sizeof(*msg))) {
            fprintf(stderr, "enqueue failed (full or deleting), freeing id=%d\n",
                    msg->id);
            free(msg);
        }
    }
}

int
main(void) {

    ll_event_dispatcher_t ev_dis;
    ll_pkt_q_t high_q, low_q;

    /* 1. Init dispatcher; pin its thread to core 0 (default). */
    if (!ll_event_dispatcher_init(&ev_dis, "usage", /*core_id=*/0)) {
        fprintf(stderr, "ll_event_dispatcher_init failed\n");
        return 1;
    }

    /* 2. Register pkt_qs: callback + priority + optional free_fn. */
    if (!ll_init_pkt_q(&ev_dis, &high_q, pkt_q_callback,
                       LL_TASK_PRIORITY_HIGH, app_msg_free) ||
        !ll_init_pkt_q(&ev_dis, &low_q, pkt_q_callback,
                       LL_TASK_PRIORITY_LOW, app_msg_free)) {
        fprintf(stderr, "ll_init_pkt_q failed\n");
        return 1;
    }

    /* 3. Start the consumer thread (pinned to core_id from init). */
    ll_event_dispatcher_run(&ev_dis);

    /* 4. Enqueue from the main thread and a worker thread. */
    producer(&ev_dis, &low_q, 100, 3);   /* lower priority */

    std::thread t(producer, &ev_dis, &high_q, 1, 5);
    t.join();

    /* Give the dispatcher a moment to drain. */
    usleep(200 * 1000);

    printf("\n--- scheduler snapshot ---\n");
    ll_scheduler_task_queue(&ev_dis);

    /* 5. Tear down: de-init every pkt_q, then destroy the dispatcher. */
    ll_de_init_pkt_q(&high_q);
    ll_de_init_pkt_q(&low_q);
    ll_event_dispatcher_destroy(&ev_dis);

    printf("done.\n");
    return 0;
}
