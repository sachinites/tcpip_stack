/*
 * =====================================================================================
 *
 *       Filename:  LockLessEvDis_test.cpp
 *
 *    Description:  Rigorous self-checking tests of the lock-less Event Dispatcher.
 *
 *                  Demo 1  : Basic usage (scaled volume, exact delivery)
 *                  Demo 2  : Priority across all levels + multi-cycle order
 *                  Demo 3  : Multi-producer / multi-queue MPSC stress
 *                            (per-producer FIFO, zero loss, drop accounting)
 *                  Demo 4  : Wait / Signal (idle sleep, concurrent wake races)
 *                  Demo 5  : Deleting a pkt_q while producers hammer it
 *                  Demo 6  : Same-priority round-robin fairness
 *                  Demo 7  : Full-queue drops and exact capacity
 *                  Demo 8  : Cooperative yield + re-schedule under sustained
 *                            producer pressure (no stranded packets)
 *                  Demo 9  : Many pkt_qs near LL_EV_DIS_MAX_PKT_Q
 *                  Demo 10 : Self-delete from inside own callback under load
 *                  Demo 11 : Passive queue (cbk == NULL) is never scheduled
 *
 *       Build   :  ./compile_ll.sh
 *       Run     :  ./ll_ev_dis_test.exe              (all demos, scale=1)
 *                  ./ll_ev_dis_test.exe 3            (only demo 3)
 *                  ./ll_ev_dis_test.exe 0 4          (all demos, scale=4)
 *                  ./ll_ev_dis_test.exe 3 8          (demo 3, scale=8)
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
#include <algorithm>
#include <memory>
#include <cstdint>

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

/* Global scale factor (1 = baseline). Volumes grow roughly linearly. */
static int g_scale = 1;

static int
scaled(int base) {
    return base * (g_scale < 1 ? 1 : g_scale);
}

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
        usleep(200);
    }
    return true;
}

static bool
wait_until(std::atomic<bool> &flag, bool want, double timeout_sec) {

    double deadline = now_sec() + timeout_sec;
    while (flag.load() != want) {
        if (now_sec() > deadline) return false;
        usleep(200);
    }
    return true;
}

static void
noop_free(void *) { }

/* ====================================================================== */
/* Demo 1 : Basic usage (scaled)                                           */
/* ====================================================================== */

static std::atomic<uint64_t> d1_rcvd(0);
static std::atomic<uint64_t> d1_bytes(0);

static void
d1_pkt_receiver(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg; (void)arg_size;
    uint32_t pkt_size;
    char *pkt;

    while ((pkt = ll_task_get_next_pkt(ev_dis, &pkt_size))) {
        d1_bytes += pkt_size;
        free(pkt);
        d1_rcvd++;
    }
}

static void
demo1_basic(void) {

    const int n_queues = scaled(8);
    const int pkts_per_q = scaled(5000);
    const uint64_t expected = (uint64_t)n_queues * pkts_per_q;

    printf("\n=== Demo 1 : Basic usage (%d queues x %d pkts) ===\n",
           n_queues, pkts_per_q);

    ll_event_dispatcher_t ev_dis;
    std::unique_ptr<ll_pkt_q_t[]> qs(new ll_pkt_q_t[n_queues]());

    d1_rcvd = 0;
    d1_bytes = 0;

    CHECK(ll_event_dispatcher_init(&ev_dis, "demo1"), "init failed");
    for (int q = 0; q < n_queues; q++) {
        CHECK(ll_init_pkt_q(&ev_dis, &qs[q], d1_pkt_receiver), "q%d", q);
    }
    ll_event_dispatcher_run(&ev_dis);

    uint64_t expected_bytes = 0;
    for (int q = 0; q < n_queues; q++) {
        for (int i = 0; i < pkts_per_q; i++) {
            char buf[64];
            int n = snprintf(buf, sizeof(buf), "q%d-pkt%d", q, i);
            char *pkt = strdup(buf);
            CHECK(pkt, "strdup");
            while (!ll_pkt_q_enqueue(&ev_dis, &qs[q], pkt, (uint32_t)(n + 1))) {
                sched_yield();
            }
            expected_bytes += (uint32_t)(n + 1);
        }
    }

    CHECK(wait_for(d1_rcvd, expected, 30.0),
          "only %lu of %lu pkts received",
          (unsigned long)d1_rcvd.load(), (unsigned long)expected);
    CHECK(d1_bytes.load() == expected_bytes,
          "byte tally mismatch %lu vs %lu",
          (unsigned long)d1_bytes.load(), (unsigned long)expected_bytes);
    CHECK(ll_eve_dis_get_current_pkt_q(&ev_dis) == NULL,
          "current pkt_q should be NULL when idle");

    for (int q = 0; q < n_queues; q++) {
        CHECK(ll_pkt_q_count(&qs[q]) == 0, "q%d not drained", q);
        CHECK(qs[q].deq_count == (uint64_t)pkts_per_q,
              "q%d deq_count %lu", q, (unsigned long)qs[q].deq_count);
        ll_de_init_pkt_q(&qs[q]);
    }
    ll_event_dispatcher_destroy(&ev_dis);
    printf("    received %lu pkts / %lu bytes  PASS\n",
           (unsigned long)expected, (unsigned long)expected_bytes);
}

/* ====================================================================== */
/* Demo 2 : Priority (all levels, multi-cycle)                             */
/* ====================================================================== */

/*
 * Keep the dispatcher busy inside a blocker callback, enqueue one packet
 * per priority from LOWEST to HIGHEST, then release. Service order must be
 * CRITICAL .. VERY_LOW regardless of enqueue order. Repeat for several
 * cycles to catch sticky scheduling bugs.
 */
static std::atomic<bool> d2_blocker_running(false);
static std::atomic<bool> d2_release_blocker(false);
static char d2_order[LL_TASK_PRIORITY_MAX + 1];
static int d2_order_len;
static std::atomic<uint64_t> d2_rcvd(0);

static const ll_task_priority_t d2_prios[] = {
    LL_TASK_PRIORITY_CRITICAL,
    LL_TASK_PRIORITY_HIGH,
    LL_TASK_PRIORITY_MEDIUM,
    LL_TASK_PRIORITY_LOW_MEDIUM,
    LL_TASK_PRIORITY_LOW,
    LL_TASK_PRIORITY_VERY_LOW,
};
static const int d2_n_prios = (int)(sizeof(d2_prios) / sizeof(d2_prios[0]));

static void
d2_blocker_cbk(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg; (void)arg_size;
    uint32_t sz;
    while (ll_task_get_next_pkt(ev_dis, &sz)) { }
    d2_blocker_running = true;
    while (!d2_release_blocker.load()) usleep(200);
}

static void
d2_tagged_cbk(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg; (void)arg_size;
    uint32_t sz;
    char *pkt;
    while ((pkt = ll_task_get_next_pkt(ev_dis, &sz))) {
        d2_order[d2_order_len++] = pkt[0];
        d2_rcvd++;
    }
}

static void
demo2_priority(void) {

    const int cycles = scaled(20);
    printf("\n=== Demo 2 : Priority (%d cycles x %d levels) ===\n",
           cycles, d2_n_prios);

    ll_event_dispatcher_t ev_dis;
    ll_pkt_q_t blocker_q;
    ll_pkt_q_t qs[LL_TASK_PRIORITY_MAX];
    static char tags[LL_TASK_PRIORITY_MAX][2];
    static char dummy[] = "x";

    for (int i = 0; i < d2_n_prios; i++) {
        tags[i][0] = (char)('0' + i);
        tags[i][1] = '\0';
    }

    CHECK(ll_event_dispatcher_init(&ev_dis, "demo2"), "init");
    CHECK(ll_init_pkt_q(&ev_dis, &blocker_q, d2_blocker_cbk,
                        LL_TASK_PRIORITY_VERY_LOW, noop_free), "blocker");
    for (int i = 0; i < d2_n_prios; i++) {
        CHECK(ll_init_pkt_q(&ev_dis, &qs[i], d2_tagged_cbk, d2_prios[i], noop_free),
              "q%d", i);
    }
    ll_event_dispatcher_run(&ev_dis);

    char expected[LL_TASK_PRIORITY_MAX + 1];
    for (int i = 0; i < d2_n_prios; i++) expected[i] = (char)('0' + i);
    expected[d2_n_prios] = '\0';

    for (int c = 0; c < cycles; c++) {
        d2_blocker_running = false;
        d2_release_blocker = false;
        d2_order_len = 0;
        d2_rcvd = 0;
        memset(d2_order, 0, sizeof(d2_order));

        CHECK(ll_pkt_q_enqueue(&ev_dis, &blocker_q, dummy, sizeof(dummy)),
              "blocker enqueue cycle %d", c);
        CHECK(wait_until(d2_blocker_running, true, 2.0),
              "blocker not entered cycle %d", c);

        /* Enqueue lowest priority first so wrong schedulers would serve them
         * in enqueue order rather than priority order. */
        for (int i = d2_n_prios - 1; i >= 0; i--) {
            CHECK(ll_pkt_q_enqueue(&ev_dis, &qs[i], tags[i], 2),
                  "enqueue pri %d cycle %d", i, c);
        }

        d2_release_blocker = true;
        CHECK(wait_for(d2_rcvd, (uint64_t)d2_n_prios, 2.0),
              "pkts not served cycle %d (%lu)", c, (unsigned long)d2_rcvd.load());
        d2_order[d2_order_len] = '\0';
        CHECK(strcmp(d2_order, expected) == 0,
              "cycle %d wrong order %s (expected %s)", c, d2_order, expected);
    }

    printf("    service order every cycle = %s\n", expected);

    ll_de_init_pkt_q(&blocker_q);
    for (int i = 0; i < d2_n_prios; i++) ll_de_init_pkt_q(&qs[i]);
    ll_event_dispatcher_destroy(&ev_dis);
    printf("    PASS\n");
}

/* ====================================================================== */
/* Demo 3 : MPSC stress                                                    */
/* ====================================================================== */

/*
 * A "packet" is not a real buffer: the pointer carries the sequence number
 * and pkt_size carries the producer id. The dispatcher never dereferences.
 */
static int d3_n_producers;
static int d3_n_queues;
static int64_t d3_pkts_per_prod_per_q;

static std::atomic<uint64_t> d3_rcvd(0);
static std::vector<std::vector<int64_t>> d3_last_seq;
static std::atomic<uint64_t> d3_fifo_violations(0);
static std::unique_ptr<ll_pkt_q_t[]> d3_q;

static void
d3_cbk(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg_size;
    ll_pkt_q_t *pkt_q = (ll_pkt_q_t *)arg;
    int qid = (int)(pkt_q - d3_q.get());
    uint32_t prod_id;
    char *pkt;
    uint64_t n = 0;

    while ((pkt = ll_task_get_next_pkt(ev_dis, &prod_id))) {
        int64_t seq = (int64_t)(uintptr_t)pkt;
        if (prod_id >= (uint32_t)d3_n_producers) {
            d3_fifo_violations++;
        } else if (seq != d3_last_seq[qid][prod_id] + 1) {
            d3_fifo_violations++;
        }
        d3_last_seq[qid][prod_id] = seq;
        n++;

        if ((n & 1023) == 0 && ll_event_dispatcher_should_suspend(ev_dis)) break;
    }
    d3_rcvd += n;
}

static void
d3_producer(ll_event_dispatcher_t *ev_dis, uint32_t prod_id, uint64_t *retries) {

    for (int64_t seq = 1; seq <= d3_pkts_per_prod_per_q; seq++) {
        for (int q = 0; q < d3_n_queues; q++) {
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

    d3_n_producers = scaled(8);
    d3_n_queues = scaled(6);
    if (d3_n_queues > LL_EV_DIS_MAX_PKT_Q) d3_n_queues = LL_EV_DIS_MAX_PKT_Q;
    d3_pkts_per_prod_per_q = scaled(250000);

    printf("\n=== Demo 3 : %d producers x %d queues x %ld pkts (MPSC stress) ===\n",
           d3_n_producers, d3_n_queues, (long)d3_pkts_per_prod_per_q);

    ll_event_dispatcher_t ev_dis;
    d3_q.reset(new ll_pkt_q_t[d3_n_queues]());
    d3_last_seq.assign(d3_n_queues, std::vector<int64_t>(d3_n_producers, 0));
    d3_rcvd = 0;
    d3_fifo_violations = 0;

    const ll_task_priority_t prio_cycle[] = {
        LL_TASK_PRIORITY_CRITICAL, LL_TASK_PRIORITY_HIGH,
        LL_TASK_PRIORITY_MEDIUM, LL_TASK_PRIORITY_LOW_MEDIUM,
        LL_TASK_PRIORITY_LOW, LL_TASK_PRIORITY_VERY_LOW };

    CHECK(ll_event_dispatcher_init(&ev_dis, "demo3"), "init");
    for (int q = 0; q < d3_n_queues; q++) {
        CHECK(ll_init_pkt_q(&ev_dis, &d3_q[q], d3_cbk,
                            prio_cycle[q % 6], noop_free), "q%d", q);
    }
    ll_event_dispatcher_run(&ev_dis);

    std::vector<uint64_t> retries(d3_n_producers, 0);
    std::vector<std::thread> producers;
    double t0 = now_sec();

    for (uint32_t p = 0; p < (uint32_t)d3_n_producers; p++) {
        producers.emplace_back(d3_producer, &ev_dis, p, &retries[p]);
    }
    for (auto &t : producers) t.join();

    uint64_t expected = (uint64_t)d3_n_producers * d3_n_queues * d3_pkts_per_prod_per_q;
    double timeout = 30.0 + (double)expected / 1e6; /* ~1s per Mpkt slack */
    CHECK(wait_for(d3_rcvd, expected, timeout), "received %lu / %lu",
          (unsigned long)d3_rcvd.load(), (unsigned long)expected);
    double dt = now_sec() - t0;

    uint64_t total_retries = 0, total_drops = 0, total_deq = 0;
    for (int p = 0; p < d3_n_producers; p++) total_retries += retries[p];
    for (int q = 0; q < d3_n_queues; q++) {
        total_drops += ll_ptk_q_drop_count(&d3_q[q]);
        total_deq += d3_q[q].deq_count;
        CHECK(ll_pkt_q_count(&d3_q[q]) == 0, "q%d not empty", q);
    }

    printf("    packets received  : %lu / %lu\n",
           (unsigned long)d3_rcvd.load(), (unsigned long)expected);
    printf("    FIFO violations   : %lu\n",
           (unsigned long)d3_fifo_violations.load());
    printf("    queue-full drops  : %lu (all retried by producers)\n",
           (unsigned long)total_drops);
    printf("    callbacks invoked : %lu\n", (unsigned long)ev_dis.n_task_exec);
    printf("    signals sent/rcvd : %u / %u\n",
           ev_dis.signal_sent_cnt.load(), ev_dis.signal_recv_cnt);
    printf("    throughput        : %.2f Mpps\n", expected / dt / 1e6);

    CHECK(d3_rcvd.load() == expected, "count mismatch");
    CHECK(total_deq == expected, "deq_count sum %lu != %lu",
          (unsigned long)total_deq, (unsigned long)expected);
    CHECK(d3_fifo_violations.load() == 0, "FIFO order broken");
    CHECK(total_drops == total_retries, "drop accounting mismatch");
    for (int q = 0; q < d3_n_queues; q++) {
        for (int p = 0; p < d3_n_producers; p++) {
            CHECK(d3_last_seq[q][p] == d3_pkts_per_prod_per_q,
                  "q%d p%d last seq %ld", q, p, (long)d3_last_seq[q][p]);
        }
    }

    for (int q = 0; q < d3_n_queues; q++) ll_de_init_pkt_q(&d3_q[q]);
    ll_event_dispatcher_destroy(&ev_dis);
    d3_q.reset();
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

    const int wake_cycles = scaled(50);
    const int concurrent_wakers = scaled(16);

    printf("\n=== Demo 4 : Wait / Signal (%d cycles, %d concurrent wakers) ===\n",
           wake_cycles, concurrent_wakers);

    ll_event_dispatcher_t ev_dis;
    ll_pkt_q_t q;
    static char pkt[] = "wake up";

    d4_rcvd = 0;

    CHECK(ll_event_dispatcher_init(&ev_dis, "demo4"), "init");
    CHECK(ll_init_pkt_q(&ev_dis, &q, d4_cbk, LL_TASK_PRIORITY_HIGH, noop_free), "q");
    ll_event_dispatcher_run(&ev_dis);

    /* Let the dispatcher go idle and sleep. */
    usleep(150 * 1000);
    CHECK(ev_dis.sleeping.load(), "dispatcher should be sleeping (not spinning)");
    CHECK(ev_dis.ev_dis_state.load() == LL_EV_DIS_IDLE, "state should be IDLE");

    uint32_t signals_before = ev_dis.signal_sent_cnt.load();

    /* Sequential wake / sleep cycles. */
    for (int i = 1; i <= wake_cycles; i++) {
        CHECK(ll_pkt_q_enqueue(&ev_dis, &q, pkt, sizeof(pkt)), "enq %d", i);
        CHECK(wait_for(d4_rcvd, (uint64_t)i, 2.0), "pkt %d not received", i);

        /* Wait until the dispatcher has gone back to sleep. */
        double deadline = now_sec() + 2.0;
        while (!ev_dis.sleeping.load() && now_sec() < deadline) usleep(500);
        CHECK(ev_dis.sleeping.load(), "dispatcher not sleeping after cycle %d", i);
    }

    CHECK(ev_dis.signal_sent_cnt.load() >= signals_before + (uint32_t)wake_cycles,
          "expected >=1 signal per sequential wake-up (got %u, before %u)",
          ev_dis.signal_sent_cnt.load(), signals_before);

    /* Concurrent wake race: many producers enqueue while dispatcher is
     * asleep. Exactly concurrent_wakers packets must arrive; no hang. */
    uint64_t base = d4_rcvd.load();
    usleep(50 * 1000);
    CHECK(ev_dis.sleeping.load(), "should be asleep before concurrent wake");

    std::vector<std::thread> wakers;
    std::atomic<uint64_t> accepted(0);
    for (int i = 0; i < concurrent_wakers; i++) {
        wakers.emplace_back([&]() {
            if (ll_pkt_q_enqueue(&ev_dis, &q, pkt, sizeof(pkt))) accepted++;
        });
    }
    for (auto &t : wakers) t.join();

    CHECK(wait_for(d4_rcvd, base + accepted.load(), 5.0),
          "concurrent wake: got %lu / %lu",
          (unsigned long)(d4_rcvd.load() - base),
          (unsigned long)accepted.load());
    CHECK(accepted.load() == (uint64_t)concurrent_wakers,
          "some concurrent enqueues failed unexpectedly");

    printf("    sequential wakes : %d, concurrent accepted : %lu, signals sent : %u\n",
           wake_cycles, (unsigned long)accepted.load(),
           ev_dis.signal_sent_cnt.load());

    ll_de_init_pkt_q(&q);
    ll_event_dispatcher_destroy(&ev_dis);
    printf("    PASS\n");
}

/* ====================================================================== */
/* Demo 5 : Safe deletion under load                                       */
/* ====================================================================== */

static std::atomic<uint64_t> d5_consumed(0);
static std::atomic<uint64_t> d5_freed_by_deinit(0);

static void
d5_cbk(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg; (void)arg_size;
    uint32_t sz;
    char *pkt;
    /* Budgeted: leave packets queued so de_init's free_cbk path is hit. */
    for (int budget = 16; budget && (pkt = ll_task_get_next_pkt(ev_dis, &sz)); budget--) {
        free(pkt);
        d5_consumed++;
        usleep(1);
    }
}

static void
demo5_delete_under_load(void) {

    const int n_producers = scaled(8);
    const int hammer_ms = scaled(300);

    printf("\n=== Demo 5 : ll_de_init_pkt_q() vs %d producers for %dms ===\n",
           n_producers, hammer_ms);

    ll_event_dispatcher_t ev_dis;
    ll_pkt_q_t q;
    std::atomic<uint64_t> accepted(0);
    std::atomic<bool> stop_prod(false);

    d5_consumed = 0;
    d5_freed_by_deinit = 0;

    CHECK(ll_event_dispatcher_init(&ev_dis, "demo5"), "init");
    CHECK(ll_init_pkt_q(&ev_dis, &q, d5_cbk), "q");
    q.free_cbk = [](void *p) { free(p); d5_freed_by_deinit++; };
    ll_event_dispatcher_run(&ev_dis);

    std::vector<std::thread> producers;
    for (int p = 0; p < n_producers; p++) {
        producers.emplace_back([&]() {
            while (!stop_prod.load(std::memory_order_acquire)) {
                char *pkt = (char *)malloc(64);
                CHECK(pkt, "malloc");
                if (ll_pkt_q_enqueue(&ev_dis, &q, pkt, 64)) {
                    accepted++;
                    continue;
                }
                free(pkt);
                if (!q.active.load()) return;
                sched_yield();
            }
        });
    }

    usleep(hammer_ms * 1000);
    uint32_t queued_at_delete = ll_pkt_q_count(&q);
    printf("    deleting pkt_q (approx pkts queued: %u, accepted so far: %lu)\n",
           queued_at_delete, (unsigned long)accepted.load());
    ll_de_init_pkt_q(&q);
    stop_prod.store(true, std::memory_order_release);

    for (auto &t : producers) t.join();

    printf("    accepted by enqueue    : %lu\n", (unsigned long)accepted.load());
    printf("    consumed by callback   : %lu\n", (unsigned long)d5_consumed.load());
    printf("    freed by de_init       : %lu\n", (unsigned long)d5_freed_by_deinit.load());
    CHECK(accepted.load() == d5_consumed.load() + d5_freed_by_deinit.load(),
          "packet leak or double free");
    CHECK(accepted.load() > 0, "no packets accepted");
    CHECK(d5_freed_by_deinit.load() > 0 || queued_at_delete == 0,
          "expected some leftovers freed by de_init under slow consumer");

    ll_event_dispatcher_destroy(&ev_dis);
    printf("    PASS\n");
}

/* ====================================================================== */
/* Demo 6 : Same-priority round-robin                                      */
/* ====================================================================== */

/*
 * With a budgeted callback, N queues of equal priority that each receive the
 * same number of packets must each be invoked a comparable number of times
 * (round-robin at the ready-queue tail). Also verify total delivery.
 */
static std::atomic<uint64_t> d6_rcvd(0);
static std::vector<uint64_t> d6_per_q_rcvd;
static std::vector<int> d6_service_order; /* dispatcher-thread only */
static std::unique_ptr<ll_pkt_q_t[]> d6_qs;
static const int D6_BUDGET = 8;

static void
d6_cbk(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg_size;
    ll_pkt_q_t *pkt_q = (ll_pkt_q_t *)arg;
    int qid = (int)(pkt_q - d6_qs.get());
    d6_service_order.push_back(qid);
    uint32_t sz;
    char *pkt;
    uint64_t n = 0;
    for (int budget = D6_BUDGET; budget && (pkt = ll_task_get_next_pkt(ev_dis, &sz));
         budget--) {
        n++;
    }
    d6_per_q_rcvd[qid] += n;
    d6_rcvd += n;
}

static std::atomic<bool> d6_blk_run(false);
static std::atomic<bool> d6_blk_rel(false);

static void
d6_blocker_cbk(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg; (void)arg_size;
    uint32_t sz;
    while (ll_task_get_next_pkt(ev_dis, &sz)) { }
    d6_blk_run = true;
    while (!d6_blk_rel.load()) usleep(200);
}

static void
demo6_round_robin(void) {

    const int n_queues = scaled(8);
    /* Prefill depth must be a multiple of budget so every early callback
     * drains exactly D6_BUDGET packets, and small enough to fit in the ring. */
    const int rounds = scaled(16);
    const int pkts_per_q = D6_BUDGET * rounds;
    CHECK(pkts_per_q <= LL_PKT_Q_MAX_QUEUE_SIZE, "prefill exceeds ring");

    printf("\n=== Demo 6 : Same-priority round-robin (%d queues x %d pkts, %d RR rounds) ===\n",
           n_queues, pkts_per_q, rounds);

    ll_event_dispatcher_t ev_dis;
    d6_qs.reset(new ll_pkt_q_t[n_queues]());
    d6_per_q_rcvd.assign(n_queues, 0);
    d6_service_order.clear();
    d6_rcvd = 0;
    d6_blk_run = false;
    d6_blk_rel = false;

    CHECK(ll_event_dispatcher_init(&ev_dis, "demo6"), "init");
    for (int q = 0; q < n_queues; q++) {
        CHECK(ll_init_pkt_q(&ev_dis, &d6_qs[q], d6_cbk,
                            LL_TASK_PRIORITY_MEDIUM, noop_free), "q%d", q);
    }

    ll_pkt_q_t blocker;
    static char dummy[] = "x";
    CHECK(ll_init_pkt_q(&ev_dis, &blocker, d6_blocker_cbk,
                        LL_TASK_PRIORITY_CRITICAL, noop_free), "blocker");
    ll_event_dispatcher_run(&ev_dis);

    CHECK(ll_pkt_q_enqueue(&ev_dis, &blocker, dummy, sizeof(dummy)), "blk enq");
    CHECK(wait_until(d6_blk_run, true, 2.0), "blocker");

    /* Fill every queue to the same depth while held; all become ready in
     * enqueue order 0..N-1, so RR service must be 0,1,...,N-1, 0,1,... */
    for (int i = 0; i < pkts_per_q; i++) {
        for (int q = 0; q < n_queues; q++) {
            CHECK(ll_pkt_q_enqueue(&ev_dis, &d6_qs[q],
                                   (char *)(uintptr_t)(i + 1), 1),
                  "prefill q%d i%d", q, i);
        }
    }
    d6_blk_rel = true;

    uint64_t expected = (uint64_t)n_queues * pkts_per_q;
    CHECK(wait_for(d6_rcvd, expected, 10.0), "got %lu / %lu",
          (unsigned long)d6_rcvd.load(), (unsigned long)expected);

    CHECK((int)d6_service_order.size() == n_queues * rounds,
          "expected %d callbacks, got %zu",
          n_queues * rounds, d6_service_order.size());

    for (int r = 0; r < rounds; r++) {
        for (int q = 0; q < n_queues; q++) {
            int got = d6_service_order[r * n_queues + q];
            CHECK(got == q,
                  "RR order broken at round %d slot %d: got q%d (expected q%d)",
                  r, q, got, q);
        }
    }
    for (int q = 0; q < n_queues; q++) {
        CHECK(d6_per_q_rcvd[q] == (uint64_t)pkts_per_q,
              "q%d rcvd %lu", q, (unsigned long)d6_per_q_rcvd[q]);
    }

    printf("    first round service order :");
    for (int q = 0; q < n_queues; q++) printf(" %d", d6_service_order[q]);
    printf(" (repeated %d times)\n", rounds);

    ll_de_init_pkt_q(&blocker);
    for (int q = 0; q < n_queues; q++) ll_de_init_pkt_q(&d6_qs[q]);
    ll_event_dispatcher_destroy(&ev_dis);
    d6_qs.reset();
    printf("    PASS\n");
}

/* ====================================================================== */
/* Demo 7 : Capacity and drop accounting                                   */
/* ====================================================================== */

static std::atomic<uint64_t> d7_rcvd(0);
static std::atomic<bool> d7_hold(true);

static void
d7_cbk(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg; (void)arg_size;
    /* Hold until released so the ring can be filled to capacity. */
    while (d7_hold.load()) usleep(200);
    uint32_t sz;
    while (ll_task_get_next_pkt(ev_dis, &sz)) d7_rcvd++;
}

static void
demo7_capacity_drops(void) {

    printf("\n=== Demo 7 : Full-queue drops (capacity=%d) ===\n",
           LL_PKT_Q_MAX_QUEUE_SIZE);

    ll_event_dispatcher_t ev_dis;
    ll_pkt_q_t q;
    d7_rcvd = 0;
    d7_hold = true;

    CHECK(ll_event_dispatcher_init(&ev_dis, "demo7"), "init");
    CHECK(ll_init_pkt_q(&ev_dis, &q, d7_cbk, LL_TASK_PRIORITY_HIGH, noop_free), "q");
    ll_event_dispatcher_run(&ev_dis);

    /* First packet starts the (holding) callback; remaining fill the ring. */
    static char pkt[] = "x";
    CHECK(ll_pkt_q_enqueue(&ev_dis, &q, pkt, sizeof(pkt)), "first");
    usleep(20 * 1000); /* let callback start and park */

    uint64_t accepted = 1; /* the first one being held / already dequeued */
    uint64_t rejected = 0;
    /* Fill until we see consistent rejects. Ring capacity is exact. */
    for (int i = 0; i < LL_PKT_Q_MAX_QUEUE_SIZE + 200; i++) {
        if (ll_pkt_q_enqueue(&ev_dis, &q, pkt, sizeof(pkt))) accepted++;
        else rejected++;
    }

    uint32_t drops = ll_ptk_q_drop_count(&q);
    uint32_t queued = ll_pkt_q_count(&q);
    printf("    accepted=%lu rejected=%lu drops=%u queued_now=%u\n",
           (unsigned long)accepted, (unsigned long)rejected, drops, queued);

    CHECK(rejected > 0, "expected some rejects when over capacity");
    CHECK(drops == rejected, "drop_count %u != rejected %lu",
          drops, (unsigned long)rejected);
    CHECK(queued <= (uint32_t)LL_PKT_Q_MAX_QUEUE_SIZE,
          "queued %u exceeds capacity", queued);

    d7_hold = false;
    CHECK(wait_for(d7_rcvd, accepted, 5.0), "drain got %lu / %lu",
          (unsigned long)d7_rcvd.load(), (unsigned long)accepted);
    CHECK(ll_pkt_q_count(&q) == 0, "not empty after drain");

    ll_de_init_pkt_q(&q);
    ll_event_dispatcher_destroy(&ev_dis);
    printf("    PASS\n");
}

/* ====================================================================== */
/* Demo 8 : Yield + re-schedule under sustained pressure                   */
/* ====================================================================== */

static std::atomic<uint64_t> d8_rcvd(0);
static std::atomic<bool> d8_producers_done(false);

static void
d8_cbk(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg; (void)arg_size;
    uint32_t sz;
    char *pkt;
    uint64_t n = 0;
    /* Tiny budget forces frequent re-schedule via post_call. */
    for (int budget = 4; budget && (pkt = ll_task_get_next_pkt(ev_dis, &sz)); budget--) {
        n++;
    }
    d8_rcvd += n;
}

static void
demo8_yield_reschedule(void) {

    const int n_producers = scaled(8);
    const int64_t pkts_per_prod = scaled(100000);

    printf("\n=== Demo 8 : Yield/re-schedule (%d producers x %ld pkts, budget=4) ===\n",
           n_producers, (long)pkts_per_prod);

    ll_event_dispatcher_t ev_dis;
    ll_pkt_q_t q;
    d8_rcvd = 0;
    d8_producers_done = false;

    CHECK(ll_event_dispatcher_init(&ev_dis, "demo8"), "init");
    CHECK(ll_init_pkt_q(&ev_dis, &q, d8_cbk, LL_TASK_PRIORITY_HIGH, noop_free), "q");
    ll_event_dispatcher_run(&ev_dis);

    std::vector<uint64_t> retries(n_producers, 0);
    std::vector<std::thread> producers;
    for (int p = 0; p < n_producers; p++) {
        producers.emplace_back([&, p]() {
            for (int64_t seq = 1; seq <= pkts_per_prod; seq++) {
                while (!ll_pkt_q_enqueue(&ev_dis, &q,
                                         (char *)(uintptr_t)seq, (uint32_t)p)) {
                    retries[p]++;
                    sched_yield();
                }
            }
        });
    }
    for (auto &t : producers) t.join();
    d8_producers_done = true;

    uint64_t expected = (uint64_t)n_producers * pkts_per_prod;
    CHECK(wait_for(d8_rcvd, expected, 30.0), "got %lu / %lu",
          (unsigned long)d8_rcvd.load(), (unsigned long)expected);
    CHECK(ll_pkt_q_count(&q) == 0, "stranded packets remain");

    /* With budget 4, callbacks should be invoked roughly expected/4 times. */
    CHECK(ev_dis.n_task_exec >= expected / 8,
          "too few callbacks (%lu) — re-schedule may be broken",
          (unsigned long)ev_dis.n_task_exec);

    uint64_t total_retries = 0;
    for (int p = 0; p < n_producers; p++) total_retries += retries[p];
    CHECK(ll_ptk_q_drop_count(&q) == total_retries, "drop mismatch");

    printf("    rcvd=%lu callbacks=%lu drops/retries=%lu\n",
           (unsigned long)d8_rcvd.load(),
           (unsigned long)ev_dis.n_task_exec,
           (unsigned long)total_retries);

    ll_de_init_pkt_q(&q);
    ll_event_dispatcher_destroy(&ev_dis);
    printf("    PASS\n");
}

/* ====================================================================== */
/* Demo 9 : Many pkt_qs near the registry limit                            */
/* ====================================================================== */

static std::atomic<uint64_t> d9_rcvd(0);
static std::unique_ptr<ll_pkt_q_t[]> d9_qs;

static void
d9_cbk(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg; (void)arg_size;
    uint32_t sz;
    while (ll_task_get_next_pkt(ev_dis, &sz)) d9_rcvd++;
}

static void
demo9_many_queues(void) {

    /* Leave a little headroom below the hard cap for the test's own sanity. */
    int n_queues = LL_EV_DIS_MAX_PKT_Q;
    if (g_scale > 1) {
        /* Already at max; scale instead increases pkts per queue. */
    }
    const int pkts_per_q = scaled(200);

    printf("\n=== Demo 9 : %d pkt_qs (max=%d) x %d pkts ===\n",
           n_queues, LL_EV_DIS_MAX_PKT_Q, pkts_per_q);

    ll_event_dispatcher_t ev_dis;
    d9_qs.reset(new ll_pkt_q_t[n_queues]());
    d9_rcvd = 0;

    CHECK(ll_event_dispatcher_init(&ev_dis, "demo9"), "init");
    for (int q = 0; q < n_queues; q++) {
        ll_task_priority_t pri = (ll_task_priority_t)(q % LL_TASK_PRIORITY_MAX);
        CHECK(ll_init_pkt_q(&ev_dis, &d9_qs[q], d9_cbk, pri, noop_free),
              "init q%d failed (n_pkt_q=%u)", q, ev_dis.n_pkt_q);
    }

    /* One more must fail. */
    ll_pkt_q_t overflow;
    CHECK(!ll_init_pkt_q(&ev_dis, &overflow, d9_cbk),
          "expected init failure at MAX+1");

    ll_event_dispatcher_run(&ev_dis);

    std::vector<std::thread> producers;
    const int n_prod = scaled(4);
    for (int p = 0; p < n_prod; p++) {
        producers.emplace_back([&, p]() {
            for (int q = p; q < n_queues; q += n_prod) {
                for (int i = 0; i < pkts_per_q; i++) {
                    while (!ll_pkt_q_enqueue(&ev_dis, &d9_qs[q],
                                             (char *)(uintptr_t)(i + 1), 1)) {
                        sched_yield();
                    }
                }
            }
        });
    }
    for (auto &t : producers) t.join();

    uint64_t expected = (uint64_t)n_queues * pkts_per_q;
    CHECK(wait_for(d9_rcvd, expected, 60.0), "got %lu / %lu",
          (unsigned long)d9_rcvd.load(), (unsigned long)expected);

    for (int q = 0; q < n_queues; q++) {
        CHECK(ll_pkt_q_count(&d9_qs[q]) == 0, "q%d not empty", q);
        ll_de_init_pkt_q(&d9_qs[q]);
    }
    CHECK(ev_dis.n_pkt_q == 0, "registry not empty after de_init all");

    ll_event_dispatcher_destroy(&ev_dis);
    d9_qs.reset();
    printf("    PASS\n");
}

/* ====================================================================== */
/* Demo 10 : Self-delete from own callback under load                      */
/* ====================================================================== */

static std::atomic<uint64_t> d10_consumed(0);
static std::atomic<uint64_t> d10_freed(0);
static std::atomic<bool> d10_deleted(false);

static void
d10_cbk(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg_size;
    ll_pkt_q_t *pkt_q = (ll_pkt_q_t *)arg;
    uint32_t sz;
    char *pkt;
    int budget = 32;
    while (budget-- && (pkt = ll_task_get_next_pkt(ev_dis, &sz))) {
        free(pkt);
        d10_consumed++;
    }
    /* After some traffic, delete ourselves from inside the callback. */
    if (d10_consumed.load() >= (uint64_t)scaled(1000) && !d10_deleted.exchange(true)) {
        CHECK(ll_eve_dis_get_current_pkt_q(ev_dis) == pkt_q,
              "current pkt_q mismatch during self-delete");
        ll_de_init_pkt_q(pkt_q);
    }
}

static void
demo10_self_delete(void) {

    const int n_producers = scaled(4);

    printf("\n=== Demo 10 : Self-delete from callback (%d producers) ===\n",
           n_producers);

    ll_event_dispatcher_t ev_dis;
    /* Heap-allocate so self-delete + later non-touch is well-defined. */
    ll_pkt_q_t *q = new ll_pkt_q_t();
    std::atomic<uint64_t> accepted(0);

    d10_consumed = 0;
    d10_freed = 0;
    d10_deleted = false;

    CHECK(ll_event_dispatcher_init(&ev_dis, "demo10"), "init");
    CHECK(ll_init_pkt_q(&ev_dis, q, d10_cbk), "q");
    q->free_cbk = [](void *p) { free(p); d10_freed++; };
    ll_event_dispatcher_run(&ev_dis);

    std::vector<std::thread> producers;
    for (int p = 0; p < n_producers; p++) {
        producers.emplace_back([&]() {
            while (!d10_deleted.load(std::memory_order_acquire) || q->active.load()) {
                if (d10_deleted.load(std::memory_order_acquire) && !q->active.load())
                    return;
                char *pkt = (char *)malloc(32);
                CHECK(pkt, "malloc");
                if (ll_pkt_q_enqueue(&ev_dis, q, pkt, 32)) {
                    accepted++;
                } else {
                    free(pkt);
                    if (!q->active.load()) return;
                    sched_yield();
                }
            }
        });
    }

    CHECK(wait_until(d10_deleted, true, 10.0), "self-delete never happened");
    for (auto &t : producers) t.join();

    /* Give the dispatcher a moment to finish post-delete bookkeeping. */
    usleep(50 * 1000);

    printf("    accepted=%lu consumed=%lu freed_by_deinit=%lu\n",
           (unsigned long)accepted.load(),
           (unsigned long)d10_consumed.load(),
           (unsigned long)d10_freed.load());
    CHECK(accepted.load() == d10_consumed.load() + d10_freed.load(),
          "leak/double-free on self-delete");
    CHECK(d10_deleted.load(), "delete flag");
    CHECK(ev_dis.n_pkt_q == 0, "pkt_q still registered");

    delete q;
    ll_event_dispatcher_destroy(&ev_dis);
    printf("    PASS\n");
}

/* ====================================================================== */
/* Demo 11 : Passive queue never scheduled                                  */
/* ====================================================================== */

static std::atomic<uint64_t> d11_active_rcvd(0);

static void
d11_active_cbk(ll_event_dispatcher_t *ev_dis, void *arg, uint32_t arg_size) {

    (void)arg; (void)arg_size;
    uint32_t sz;
    while (ll_task_get_next_pkt(ev_dis, &sz)) d11_active_rcvd++;
}

static void
demo11_passive_queue(void) {

    /* Passive queues are never drained by the dispatcher, so fill exactly to
     * capacity and confirm an overflow drops without ever scheduling. */
    const int n_passive = LL_PKT_Q_MAX_QUEUE_SIZE;
    const int n_active = scaled(1000);
    printf("\n=== Demo 11 : Passive queue (cbk==NULL), fill %d + overflow ===\n",
           n_passive);

    ll_event_dispatcher_t ev_dis;
    ll_pkt_q_t passive, active;
    d11_active_rcvd = 0;

    CHECK(ll_event_dispatcher_init(&ev_dis, "demo11"), "init");
    CHECK(ll_init_pkt_q(&ev_dis, &passive, NULL, LL_TASK_PRIORITY_CRITICAL, noop_free),
          "passive");
    CHECK(ll_init_pkt_q(&ev_dis, &active, d11_active_cbk,
                        LL_TASK_PRIORITY_LOW, noop_free), "active");
    ll_event_dispatcher_run(&ev_dis);

    static char pkt[] = "p";
    for (int i = 0; i < n_passive; i++) {
        CHECK(ll_pkt_q_enqueue(&ev_dis, &passive, pkt, sizeof(pkt)),
              "passive enq %d", i);
    }
    CHECK(!ll_pkt_q_enqueue(&ev_dis, &passive, pkt, sizeof(pkt)),
          "passive overflow should fail");
    CHECK(ll_ptk_q_drop_count(&passive) == 1, "expected 1 passive drop");

    for (int i = 0; i < n_active; i++) {
        while (!ll_pkt_q_enqueue(&ev_dis, &active, pkt, sizeof(pkt)))
            sched_yield();
    }

    CHECK(wait_for(d11_active_rcvd, (uint64_t)n_active, 5.0), "active not drained");
    usleep(50 * 1000);

    CHECK(ll_pkt_q_count(&passive) == (uint32_t)n_passive,
          "passive should still hold all %d pkts (got %u)",
          n_passive, ll_pkt_q_count(&passive));
    CHECK(passive.no_of_invocations == 0, "passive callback invoked?");
    CHECK(!passive.scheduled.load(), "passive must never become scheduled");
    int ready = ll_scheduler_task_queue(&ev_dis);
    CHECK(ready == 0, "ready queues should be empty (got %d)", ready);

    ll_de_init_pkt_q(&passive);
    ll_de_init_pkt_q(&active);
    ll_event_dispatcher_destroy(&ev_dis);
    printf("    PASS (passive retained %d pkts, never scheduled)\n", n_passive);
}

/* ====================================================================== */

int
main(int argc, char **argv) {

    int only = 0;
    if (argc > 1) only = atoi(argv[1]);
    if (argc > 2) g_scale = atoi(argv[2]);
    if (g_scale < 1) g_scale = 1;

    printf("LockLessEvDis tests  (scale=%d%s)\n",
           g_scale, only ? "" : ", all demos");

    if (!only || only == 1)  demo1_basic();
    if (!only || only == 2)  demo2_priority();
    if (!only || only == 3)  demo3_mpsc_stress();
    if (!only || only == 4)  demo4_wait_signal();
    if (!only || only == 5)  demo5_delete_under_load();
    if (!only || only == 6)  demo6_round_robin();
    if (!only || only == 7)  demo7_capacity_drops();
    if (!only || only == 8)  demo8_yield_reschedule();
    if (!only || only == 9)  demo9_many_queues();
    if (!only || only == 10) demo10_self_delete();
    if (!only || only == 11) demo11_passive_queue();

    printf("\nAll requested demos passed (scale=%d).\n", g_scale);
    return 0;
}
