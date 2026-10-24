/*
 * =====================================================================================
 *
 *       Filename:  LockLessEvDis_usage.cpp
 *
 *    Description:  Minimal sample showing how to use the lock-less Event
 *                  Dispatcher. Application code includes PubLockLessEvDis.h only.
 *                  Dispatcher and pkt_q handles are opaque (create/destroy/free).
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

#include "PubLockLessEvDis.h"

typedef struct app_msg_ {
    int  id;
    char text[64];
} app_msg_t;

static void
app_msg_free(void *p) {

    free(p);
}

static void
pkt_q_callback(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg_size;
    ll_pkt_q_t *pkt_q = (ll_pkt_q_t *)arg;
    uint32_t pkt_size;
    char *raw;

    while ((raw = ll_task_get_next_pkt(ev_dis, &pkt_size)) != NULL) {

        app_msg_t *msg = (app_msg_t *)raw;
        printf("[dispatcher] pkt_q=%p  msg id=%d text=\"%s\" (%u bytes)\n",
               (void *)pkt_q, msg->id, msg->text, pkt_size);

        free(msg);

        if (ll_event_dispatcher_should_suspend(ev_dis)) {
            printf("[dispatcher] yielding (preempt interval)\n");
            break;
        }
    }
}

static void
producer(ll_event_dispatcher_t *ev_dis, ll_pkt_q_t *pkt_q,
         int start_id, int count) {

    for (int i = 0; i < count; i++) {
        app_msg_t *msg = (app_msg_t *)malloc(sizeof(*msg));
        if (!msg) continue;

        msg->id = start_id + i;
        snprintf(msg->text, sizeof(msg->text), "hello from producer, id=%d",
                 msg->id);

        if (!ll_pkt_q_enqueue(ev_dis, pkt_q, (char *)msg, sizeof(*msg))) {
            fprintf(stderr, "enqueue failed (full or deleting), freeing id=%d\n",
                    msg->id);
            free(msg);
        }
    }
}

int
main(void) {

    ll_event_dispatcher_t *ev_dis =
        ll_event_dispatcher_create("usage", /*core_id=*/0);
    if (!ev_dis) {
        fprintf(stderr, "ll_event_dispatcher_create failed\n");
        return 1;
    }

    ll_pkt_q_t *high_q = ll_pkt_q_create(ev_dis, pkt_q_callback,
                                         LL_TASK_PRIORITY_HIGH, app_msg_free);
    ll_pkt_q_t *low_q = ll_pkt_q_create(ev_dis, pkt_q_callback,
                                        LL_TASK_PRIORITY_LOW, app_msg_free);
    if (!high_q || !low_q) {
        fprintf(stderr, "ll_pkt_q_create failed\n");
        return 1;
    }

    ll_event_dispatcher_run(ev_dis);

    producer(ev_dis, low_q, 100, 3);

    std::thread t(producer, ev_dis, high_q, 1, 5);
    t.join();

    usleep(200 * 1000);

    printf("\n--- scheduler snapshot ---\n");
    ll_scheduler_task_queue(ev_dis);

    ll_pkt_q_destroy(high_q);
    ll_pkt_q_destroy(low_q);
    ll_pkt_q_free(high_q);
    ll_pkt_q_free(low_q);
    ll_event_dispatcher_destroy(ev_dis);

    printf("done.\n");
    return 0;
}
