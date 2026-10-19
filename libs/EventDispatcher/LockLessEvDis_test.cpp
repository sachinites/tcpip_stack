/*
 * =====================================================================================
 *
 *       Filename:  LockLessEvDis_test.cpp
 *
 *    Description:  Demo + self-checking test of the lock-less Event Dispatcher.
 *
 *                  Demo 1 : Basic usage (port of main_pkt_q.c)
 *                  Demo 2 : Priority is honoured
 *                  Demo 3 : Multi-producer / single-consumer stress with
 *                           per-producer FIFO and "no packet lost" checks
 *                  Demo 4 : Wait / Signal (dispatcher sleeps when idle)
 *                  Demo 5 : Deleting a pkt_q while producers are hammering it
 *
 *       Build   :  ./compile_ll.sh
 *       Run     :  ./ll_ev_dis_test.exe          (all demos)
 *                  ./ll_ev_dis_test.exe 3        (only demo 3)
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <atomic>
#include <thread>
#include <vector>

#include "LockLessEvDis.h"

#define CHECK(cond, ...)                                              \
    do {                                                              \
        if (!(cond)) {                                                \
            printf("    FAIL (%s:%d) : ", __FILE__, __LINE__);        \
            printf(__VA_ARGS__);                                      \
            printf("\n");                                             \
            exit(1);                                                  \
        }                                                             \
    } while (0)

static double
now_sec(void) {

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Wait (up to timeout) until counter reaches target. */
static bool
wait_for(std::atomic<uint64_t> &counter, uint64_t target, double timeout_sec) {

    double deadline = now_sec() + timeout_sec;
    while (counter.load() < target) {
        if (now_sec() > deadline) return false;
        usleep(1000);
    }
    return true;
}

/* ====================================================================== */
/* Demo 1 : Basic usage                                                    */
/* ====================================================================== */

static std::atomic<uint64_t> d1_rcvd(0);

/* A callback has the same shape as in the original dispatcher: drain the
 * current pkt_q with ll_task_get_next_pkt() until it returns NULL. */
static void
d1_pkt_receiver(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg_size;
    ll_pkt_q_t *pkt_q = (ll_pkt_q_t *)arg;
    uint32_t pkt_size;
    char *pkt;

    while ((pkt = ll_task_get_next_pkt(ev_dis, &pkt_size))) {
        printf("    [dispatcher] pkt_q %p (pri %d) received : \"%s\" (%u bytes)\n",
               (void *)pkt_q, pkt_q->priority, pkt, pkt_size);
        free(pkt);
        d1_rcvd++;
    }
}

static void
demo1_basic(void) {

    printf("\n=== Demo 1 : Basic usage ===\n");

    static ll_event_dispatcher_t ev_dis;
    static ll_pkt_q_t q1, q2, q3;

    CHECK(ll_event_dispatcher_init(&ev_dis, "demo1"), "init failed");
    CHECK(ll_init_pkt_q(&ev_dis, &q1, d1_pkt_receiver), "q1");
    CHECK(ll_init_pkt_q(&ev_dis, &q2, d1_pkt_receiver), "q2");
    CHECK(ll_init_pkt_q(&ev_dis, &q3, d1_pkt_receiver), "q3");
    ll_event_dispatcher_run(&ev_dis, false, -1);

    const char *msgs[] = { "first pkt", "second pkt", "third pkt" };
    ll_pkt_q_t *qs[] = { &q1, &q2, &q3 };

    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 3; j++) {
            char *pkt = strdup(msgs[j]);
            /* Packets are owned by the dispatcher once enqueue succeeds. */
            if (!ll_pkt_q_enqueue(&ev_dis, qs[j], pkt, strlen(pkt) + 1)) free(pkt);
        }
    }

    CHECK(wait_for(d1_rcvd, 6, 2.0), "only %lu of 6 pkts received",
          (unsigned long)d1_rcvd.load());

    ll_de_init_pkt_q(&q1);
    ll_de_init_pkt_q(&q2);
    ll_de_init_pkt_q(&q3);
    ll_event_dispatcher_destroy(&ev_dis);
    printf("    PASS\n");
}

/* ====================================================================== */
/* Demo 2 : Priority                                                       */
/* ====================================================================== */

/*
 * Idea: keep the dispatcher busy inside a "blocker" callback, enqueue to a
 * LOW, then MEDIUM, then CRITICAL queue (lowest priority first!), then let
 * the blocker finish. The dispatcher must serve CRITICAL, MEDIUM, LOW.
 */
static std::atomic<bool> d2_blocker_running(false);
static std::atomic<bool> d2_release_blocker(false);
static char d2_order[8];
static int d2_order_len;
static std::atomic<uint64_t> d2_rcvd(0);

static void
d2_blocker_cbk(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg; (void)arg_size;
    uint32_t sz;
    while (ll_task_get_next_pkt(ev_dis, &sz)) { }
    d2_blocker_running = true;
    while (!d2_release_blocker) usleep(1000);
}

static void
d2_tagged_cbk(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg; (void)arg_size;
    uint32_t sz;
    char *pkt;
    while ((pkt = ll_task_get_next_pkt(ev_dis, &sz))) {
        /* Callbacks are serialized: no lock needed to append. */
        d2_order[d2_order_len++] = pkt[0];
        printf("    [dispatcher] served queue '%c'\n", pkt[0]);
        d2_rcvd++;
    }
}

static void
demo2_priority(void) {

    printf("\n=== Demo 2 : Priority ===\n");

    static ll_event_dispatcher_t ev_dis;
    static ll_pkt_q_t blocker_q, crit_q, med_q, low_q;
    static char tag_c[] = "C", tag_m[] = "M", tag_l[] = "L", dummy[] = "x";

    CHECK(ll_event_dispatcher_init(&ev_dis, "demo2"), "init");
    CHECK(ll_init_pkt_q(&ev_dis, &blocker_q, d2_blocker_cbk, LL_TASK_PRIORITY_VERY_LOW), "q");
    CHECK(ll_init_pkt_q(&ev_dis, &crit_q, d2_tagged_cbk, LL_TASK_PRIORITY_CRITICAL), "q");
    CHECK(ll_init_pkt_q(&ev_dis, &med_q,  d2_tagged_cbk, LL_TASK_PRIORITY_MEDIUM), "q");
    CHECK(ll_init_pkt_q(&ev_dis, &low_q,  d2_tagged_cbk, LL_TASK_PRIORITY_LOW), "q");
    /* Static strings here: do not let de_init free() them. */
    blocker_q.free_cbk = crit_q.free_cbk = med_q.free_cbk = low_q.free_cbk =
        [](void *) {};
    ll_event_dispatcher_run(&ev_dis, false, -1);

    ll_pkt_q_enqueue(&ev_dis, &blocker_q, dummy, sizeof(dummy));
    while (!d2_blocker_running) usleep(1000);
    printf("    dispatcher is busy in blocker callback; enqueueing L, M, C\n");

    ll_pkt_q_enqueue(&ev_dis, &low_q,  tag_l, sizeof(tag_l));
    ll_pkt_q_enqueue(&ev_dis, &med_q,  tag_m, sizeof(tag_m));
    ll_pkt_q_enqueue(&ev_dis, &crit_q, tag_c, sizeof(tag_c));

    ll_scheduler_task_queue(&ev_dis);

    d2_release_blocker = true;
    CHECK(wait_for(d2_rcvd, 3, 2.0), "pkts not served");
    d2_order[d2_order_len] = '\0';
    printf("    service order = %s (expected CML)\n", d2_order);
    CHECK(strcmp(d2_order, "CML") == 0, "wrong order %s", d2_order);

    ll_de_init_pkt_q(&blocker_q);
    ll_de_init_pkt_q(&crit_q);
    ll_de_init_pkt_q(&med_q);
    ll_de_init_pkt_q(&low_q);
    ll_event_dispatcher_destroy(&ev_dis);
    printf("    PASS\n");
}

/* ====================================================================== */
/* Demo 3 : MPSC stress                                                    */
/* ====================================================================== */

#define D3_N_PRODUCERS   4
#define D3_N_QUEUES      3
#define D3_PKTS_PER_PROD_PER_Q 200000

/*
 * To keep the test about the dispatcher (and not malloc), a "packet" is not
 * a real buffer: the pointer itself carries the sequence number and
 * pkt_size carries the producer id. The dispatcher never dereferences pkts.
 */
static std::atomic<uint64_t> d3_rcvd(0);
/* Last sequence number seen per (queue, producer). Touched only by the
 * dispatcher thread, so plain variables are fine. */
static int64_t d3_last_seq[D3_N_QUEUES][D3_N_PRODUCERS];
static uint64_t d3_fifo_violations;
static ll_pkt_q_t d3_q[D3_N_QUEUES];

static void
d3_cbk(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg_size;
    ll_pkt_q_t *pkt_q = (ll_pkt_q_t *)arg;
    int qid = (int)(pkt_q - d3_q);
    uint32_t prod_id;
    char *pkt;
    uint64_t n = 0;

    while ((pkt = ll_task_get_next_pkt(ev_dis, &prod_id))) {

        int64_t seq = (int64_t)(uintptr_t)pkt;
        /* Each producer enqueues seq 1,2,3... into each queue. Since the
         * ring is FIFO, per producer they must come out strictly in order. */
        if (seq != d3_last_seq[qid][prod_id] + 1) d3_fifo_violations++;
        d3_last_seq[qid][prod_id] = seq;
        n++;

        /* Cooperative yielding, exactly like the original design. */
        if ((n & 1023) == 0 && ll_event_dispatcher_should_suspend(ev_dis)) break;
    }
    d3_rcvd += n;
}

static void
d3_producer(ll_event_dispatcher_t *ev_dis, uint32_t prod_id, uint64_t *retries) {

    for (int64_t seq = 1; seq <= D3_PKTS_PER_PROD_PER_Q; seq++) {
        for (int q = 0; q < D3_N_QUEUES; q++) {
            /* On "queue full" back off and retry, so every packet is
             * eventually delivered and we can check exact counts. */
            while (!ll_pkt_q_enqueue(ev_dis, &d3_q[q],
                                     (char *)(uintptr_t)seq, prod_id)) {
                (*retries)++;
                sched_yield();
            }
        }
    }
}

static void
demo3_mpsc_stress(void) {

    printf("\n=== Demo 3 : %d producers x %d queues x %d pkts (MPSC stress) ===\n",
           D3_N_PRODUCERS, D3_N_QUEUES, D3_PKTS_PER_PROD_PER_Q);

    static ll_event_dispatcher_t ev_dis;
    ll_task_priority_t prio[D3_N_QUEUES] = {
        LL_TASK_PRIORITY_CRITICAL, LL_TASK_PRIORITY_HIGH, LL_TASK_PRIORITY_LOW };

    CHECK(ll_event_dispatcher_init(&ev_dis, "demo3"), "init");
    for (int q = 0; q < D3_N_QUEUES; q++) {
        CHECK(ll_init_pkt_q(&ev_dis, &d3_q[q], d3_cbk, prio[q]), "q");
        d3_q[q].free_cbk = [](void *) {};   /* pkts are fake pointers */
    }
    ll_event_dispatcher_run(&ev_dis, false, -1);

    uint64_t retries[D3_N_PRODUCERS] = {0};
    std::vector<std::thread> producers;
    double t0 = now_sec();

    for (uint32_t p = 0; p < D3_N_PRODUCERS; p++) {
        producers.emplace_back(d3_producer, &ev_dis, p, &retries[p]);
    }
    for (auto &t : producers) t.join();

    uint64_t expected = (uint64_t)D3_N_PRODUCERS * D3_N_QUEUES * D3_PKTS_PER_PROD_PER_Q;
    CHECK(wait_for(d3_rcvd, expected, 30.0), "received %lu / %lu",
          (unsigned long)d3_rcvd.load(), (unsigned long)expected);
    double dt = now_sec() - t0;

    uint64_t total_retries = 0, total_drops = 0;
    for (int p = 0; p < D3_N_PRODUCERS; p++) total_retries += retries[p];
    for (int q = 0; q < D3_N_QUEUES; q++) total_drops += ll_ptk_q_drop_count(&d3_q[q]);

    printf("    packets received  : %lu / %lu\n",
           (unsigned long)d3_rcvd.load(), (unsigned long)expected);
    printf("    FIFO violations   : %lu\n", (unsigned long)d3_fifo_violations);
    printf("    queue-full drops  : %lu (all retried by producers)\n",
           (unsigned long)total_drops);
    printf("    callbacks invoked : %lu\n", (unsigned long)ev_dis.n_task_exec);
    printf("    signals sent/rcvd : %u / %u\n",
           ev_dis.signal_sent_cnt.load(), ev_dis.signal_recv_cnt);
    printf("    throughput        : %.2f Mpps\n", expected / dt / 1e6);

    CHECK(d3_fifo_violations == 0, "FIFO order broken");
    CHECK(total_drops == total_retries, "drop accounting mismatch");
    for (int q = 0; q < D3_N_QUEUES; q++) {
        for (int p = 0; p < D3_N_PRODUCERS; p++) {
            CHECK(d3_last_seq[q][p] == D3_PKTS_PER_PROD_PER_Q,
                  "q%d p%d last seq %ld", q, p, (long)d3_last_seq[q][p]);
        }
    }

    for (int q = 0; q < D3_N_QUEUES; q++) ll_de_init_pkt_q(&d3_q[q]);
    ll_event_dispatcher_destroy(&ev_dis);
    printf("    PASS\n");
}

/* ====================================================================== */
/* Demo 4 : Wait / Signal                                                  */
/* ====================================================================== */

static std::atomic<uint64_t> d4_rcvd(0);

static void
d4_cbk(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg; (void)arg_size;
    uint32_t sz;
    while (ll_task_get_next_pkt(ev_dis, &sz)) d4_rcvd++;
}

static void
demo4_wait_signal(void) {

    printf("\n=== Demo 4 : Wait / Signal ===\n");

    static ll_event_dispatcher_t ev_dis;
    static ll_pkt_q_t q;
    static char pkt[] = "wake up";

    CHECK(ll_event_dispatcher_init(&ev_dis, "demo4"), "init");
    CHECK(ll_init_pkt_q(&ev_dis, &q, d4_cbk), "q");
    q.free_cbk = [](void *) {};
    ll_event_dispatcher_run(&ev_dis, false, -1);

    usleep(100 * 1000);
    printf("    after 100ms with no work  : state=%s sleeping=%d signals sent=%u\n",
           ev_dis.ev_dis_state.load() == LL_EV_DIS_IDLE ? "IDLE" : "BUSY",
           (int)ev_dis.sleeping.load(), ev_dis.signal_sent_cnt.load());
    CHECK(ev_dis.sleeping.load(), "dispatcher should be sleeping (not spinning)");

    for (int i = 1; i <= 3; i++) {
        ll_pkt_q_enqueue(&ev_dis, &q, pkt, sizeof(pkt));
        CHECK(wait_for(d4_rcvd, i, 2.0), "pkt %d not received", i);
        usleep(50 * 1000);  /* let dispatcher go back to sleep */
        printf("    enqueue #%d -> received, signals sent=%u recvd=%u, sleeping again=%d\n",
               i, ev_dis.signal_sent_cnt.load(), ev_dis.signal_recv_cnt,
               (int)ev_dis.sleeping.load());
    }
    CHECK(ev_dis.signal_sent_cnt.load() >= 3, "expected a signal per wake-up");

    ll_de_init_pkt_q(&q);
    ll_event_dispatcher_destroy(&ev_dis);
    printf("    PASS\n");
}

/* ====================================================================== */
/* Demo 5 : Safe deletion under load                                       */
/* ====================================================================== */

static std::atomic<uint64_t> d5_consumed(0);
static std::atomic<uint64_t> d5_freed_by_deinit(0);

/* Budgeted callback: handles at most 32 pkts per invocation and returns even
 * if more are pending. The dispatcher re-schedules the pkt_q at the tail of
 * its priority. Here it also guarantees that packets are still queued when
 * the pkt_q is deleted, so de_init's free_cbk path is exercised. */
static void
d5_cbk(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg; (void)arg_size;
    uint32_t sz;
    char *pkt;
    for (int budget = 32; budget && (pkt = ll_task_get_next_pkt(ev_dis, &sz)); budget--) {
        free(pkt);
        d5_consumed++;
        usleep(1);  /* slow consumer, so the queue is never empty at deletion */
    }
}

static void
demo5_delete_under_load(void) {

    printf("\n=== Demo 5 : ll_de_init_pkt_q() while 4 producers are enqueueing ===\n");

    static ll_event_dispatcher_t ev_dis;
    static ll_pkt_q_t q;
    std::atomic<uint64_t> accepted(0);

    CHECK(ll_event_dispatcher_init(&ev_dis, "demo5"), "init");
    CHECK(ll_init_pkt_q(&ev_dis, &q, d5_cbk), "q");
    q.free_cbk = [](void *p) { free(p); d5_freed_by_deinit++; };
    ll_event_dispatcher_run(&ev_dis, false, -1);

    std::vector<std::thread> producers;
    for (int p = 0; p < 4; p++) {
        producers.emplace_back([&]() {
            while (true) {
                char *pkt = (char *)malloc(64);
                if (ll_pkt_q_enqueue(&ev_dis, &q, pkt, 64)) {
                    accepted++;
                    continue;
                }
                free(pkt);
                if (!q.active.load()) return;  /* queue deleted: stop */
                sched_yield();                 /* queue full: retry */
            }
        });
    }

    usleep(200 * 1000);
    printf("    deleting pkt_q from main thread (pkts in queue now: %u)\n",
           ll_pkt_q_count(&q));
    ll_de_init_pkt_q(&q);

    for (auto &t : producers) t.join();

    printf("    accepted by enqueue    : %lu\n", (unsigned long)accepted.load());
    printf("    consumed by callback   : %lu\n", (unsigned long)d5_consumed.load());
    printf("    freed by de_init       : %lu\n", (unsigned long)d5_freed_by_deinit.load());
    CHECK(accepted.load() == d5_consumed.load() + d5_freed_by_deinit.load(),
          "packet leak or double free");

    ll_event_dispatcher_destroy(&ev_dis);
    printf("    PASS (every accepted packet was either consumed or freed exactly once)\n");
}

int
main(int argc, char **argv) {

    int only = (argc > 1) ? atoi(argv[1]) : 0;

    if (!only || only == 1) demo1_basic();
    if (!only || only == 2) demo2_priority();
    if (!only || only == 3) demo3_mpsc_stress();
    if (!only || only == 4) demo4_wait_signal();
    if (!only || only == 5) demo5_delete_under_load();

    printf("\nAll requested demos passed.\n");
    return 0;
}
