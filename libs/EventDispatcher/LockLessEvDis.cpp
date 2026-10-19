/*
 * =====================================================================================
 *
 *       Filename:  LockLessEvDis.cpp
 *
 *    Description:  Lock-less (DPDK rte_ring based) Event Dispatcher for packet
 *                  queues. Multi-Producer / Single-Consumer.
 *
 *                  See LockLessEvDis.h for the API and LockLessEvDis_Design.md
 *                  for the design walk-through.
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sched.h>

/* Not every DPDK header declares C linkage for all of its symbols. */
extern "C" {
#include <rte_ring.h>
#include <rte_ring_elem.h>
#include <rte_pause.h>
}

#include "LockLessEvDis.h"

/*
 * Compile with -DLL_EV_DIS_DEBUG to get a trace of every scheduling decision.
 * Off by default: printf on the fast path would destroy the point of being
 * lock-less (stdio takes a lock internally).
 */
#ifdef LL_EV_DIS_DEBUG
#define LL_TRACE(fmt, ...) \
    fprintf(stderr, "[ll_ev_dis] " fmt "\n", ##__VA_ARGS__)
#else
#define LL_TRACE(fmt, ...) do {} while (0)
#endif

/*
 * Producer-side synchronization mode of every ring.
 *   RING_F_MP_RTS_ENQ  : (default) "Relaxed Tail Sync". A producer that is
 *                        preempted in the middle of an enqueue does NOT
 *                        stall the other producers. Required here because
 *                        producers are ordinary, preemptible pthreads.
 *   0                  : classic DPDK MP mode. Only safe when every producer
 *                        owns a dedicated core (DPDK lcore model). With more
 *                        producer threads than CPUs it can practically
 *                        livelock; LockLessEvDis_test.cpp demo 3 under
 *                        `taskset -c 0` reproduces it.
 *   RING_F_MP_HTS_ENQ  : "Head/Tail Sync", the other preemption-friendly mode.
 * See design doc, section "Is rte_ring really lock-free?".
 * Consumer side is always RING_F_SC_DEQ: only the dispatcher thread dequeues.
 */
#ifndef LL_RING_PROD_SYNC_FLAG
#define LL_RING_PROD_SYNC_FLAG RING_F_MP_RTS_ENQ
#endif

#define LL_RING_FLAGS (LL_RING_PROD_SYNC_FLAG | RING_F_SC_DEQ | RING_F_EXACT_SZ)

/* ========================================================================== */
/*                      Ring allocation (no EAL required)                     */
/* ========================================================================== */

/*
 * rte_ring_create() allocates from DPDK hugepage memzones and therefore needs
 * rte_eal_init(). The tcpip_stack control plane is not a DPDK application, so
 * instead we allocate cache-line aligned heap memory ourselves and let
 * rte_ring_init() format it. Same ring, same algorithms, no EAL.
 *
 * capacity : exact number of elements the ring must hold (RING_F_EXACT_SZ).
 * esize    : size of one element in bytes (multiple of 4).
 */
static struct rte_ring *
ll_ring_alloc(const char *name, unsigned int capacity, unsigned int esize) {

    /* With RING_F_EXACT_SZ, DPDK internally uses the next power of 2 above
     * capacity as the real ring size; memory must be computed for that size. */
    unsigned int real_size = rte_align32pow2(capacity + 1);
    ssize_t mem_size = rte_ring_get_memsize_elem(esize, real_size);
    if (mem_size < 0) return NULL;

    void *mem = NULL;
    if (posix_memalign(&mem, RTE_CACHE_LINE_SIZE, (size_t)mem_size) != 0) {
        return NULL;
    }

    struct rte_ring *r = (struct rte_ring *)mem;
    if (rte_ring_init(r, name, capacity, LL_RING_FLAGS) != 0) {
        free(mem);
        return NULL;
    }
    return r;
}

static void
ll_ring_free(struct rte_ring *r) {

    free(r);
}

/* ========================================================================== */
/*                              Wait / Signal                                 */
/* ========================================================================== */

static bool
ll_ready_queues_empty(ll_event_dispatcher_t *ev_dis) {

    for (int pri = LL_TASK_PRIORITY_FIRST; pri < LL_TASK_PRIORITY_MAX; pri++) {
        if (!rte_ring_empty(ev_dis->ready_q[pri])) return false;
    }
    return true;
}

/*
 * PRODUCER side of Wait/Signal. Called right after a pkt_q was pushed into a
 * ready queue.
 *
 * Fast path: the dispatcher is awake (busy running callbacks), so `sleeping`
 * is false and we return WITHOUT touching the mutex. Under load this is the
 * common case, which is why the fast path is lock-free.
 *
 * Why no wake-up is ever lost (the "store -> fence -> load" handshake):
 *   Producer:   push pkt_q into ready ring ; FENCE ; read  `sleeping`
 *   Dispatcher: write `sleeping` = true    ; FENCE ; read  ready rings
 * With a full (seq_cst) fence on both sides, at least one of the two threads
 * must see the other's write. Either the producer sees sleeping == true and
 * signals, or the dispatcher sees the non-empty ring and does not sleep.
 *
 * The producer takes the mutex before signalling because the dispatcher
 * holds it from setting `sleeping` until it is inside pthread_cond_wait().
 * So by the time the producer gets the mutex, the dispatcher is truly
 * waiting and the signal cannot be missed.
 */
static void
ll_ev_dis_wakeup(ll_event_dispatcher_t *ev_dis) {

    std::atomic_thread_fence(std::memory_order_seq_cst);

    if (!ev_dis->sleeping.load(std::memory_order_relaxed)) {
        return;
    }

    pthread_mutex_lock(&ev_dis->ev_dis_mutex);
    pthread_cond_signal(&ev_dis->ev_dis_cond_wait);
    ev_dis->signal_sent_cnt.fetch_add(1, std::memory_order_relaxed);
    pthread_mutex_unlock(&ev_dis->ev_dis_mutex);

    LL_TRACE("%s : signal sent to dispatcher", ev_dis->name);
}

/*
 * DISPATCHER side of Wait/Signal. Called when all ready queues looked empty.
 * Returns when there may be work, a deletion request, or a stop request.
 */
static void
ll_ev_dis_wait_for_work(ll_event_dispatcher_t *ev_dis) {

    pthread_mutex_lock(&ev_dis->ev_dis_mutex);

    ev_dis->sleeping.store(true, std::memory_order_relaxed);
    std::atomic_thread_fence(std::memory_order_seq_cst);

    /* Loop to tolerate spurious wake-ups. The rings are re-checked AFTER
     * advertising `sleeping` (see ll_ev_dis_wakeup for why). */
    while (!ev_dis->stop_req.load(std::memory_order_relaxed) &&
           ev_dis->del_req.load() == NULL &&
           ll_ready_queues_empty(ev_dis)) {

        ev_dis->ev_dis_state.store(LL_EV_DIS_IDLE, std::memory_order_relaxed);
        LL_TRACE("%s : no work, moving to IDLE", ev_dis->name);

        pthread_cond_wait(&ev_dis->ev_dis_cond_wait, &ev_dis->ev_dis_mutex);

        ev_dis->signal_recv_cnt++;
        LL_TRACE("%s : woken up, signal # %u", ev_dis->name, ev_dis->signal_recv_cnt);
    }

    ev_dis->sleeping.store(false, std::memory_order_relaxed);
    pthread_mutex_unlock(&ev_dis->ev_dis_mutex);
}

/* ========================================================================== */
/*                               Scheduling                                   */
/* ========================================================================== */

/*
 * Put pkt_q on its priority's ready queue, unless it is already there or
 * its callback is running. Called by producers (after enqueueing a pkt) and
 * by the dispatcher (when a callback returns with pkts still pending).
 *
 * This is the lock-less equivalent of event_dispatcher_schedule_task() in
 * the original, which took ev_dis_mutex and checked whether task->glue was
 * already linked into a list.
 */
static void
ll_pkt_q_schedule(ll_event_dispatcher_t *ev_dis, ll_pkt_q_t *pkt_q) {

    /* Passive queue: somebody polls it explicitly, never schedule. */
    if (!pkt_q->cbk) return;

    /* Only the thread that flips scheduled false->true may push the pkt_q.
     * Everyone else can return immediately: the pkt_q is either already in
     * a ready queue or being serviced, and in both cases the dispatcher
     * will see the packet they just added. */
    bool expected = false;
    if (!pkt_q->scheduled.compare_exchange_strong(expected, true,
                                                  std::memory_order_seq_cst)) {
        return;
    }

    /* Cannot fail: ready_q capacity == LL_EV_DIS_MAX_PKT_Q and the
     * `scheduled` flag guarantees each registered pkt_q is in at most one
     * ready queue, at most once. */
    int rc = rte_ring_enqueue(ev_dis->ready_q[pkt_q->priority], pkt_q);
    assert(rc == 0);
    (void)rc;

    LL_TRACE("%s : pkt_q %p added to ready queue of priority %d",
             ev_dis->name, (void *)pkt_q, pkt_q->priority);

    ll_ev_dis_wakeup(ev_dis);
}

/*
 * Pick the next pkt_q to run: scan ready queues from highest to lowest
 * priority. At most LL_TASK_PRIORITY_MAX (6) O(1) dequeue attempts, so this
 * is O(1) in the number of pkt_qs and packets.
 */
static ll_pkt_q_t *
ll_event_dispatcher_get_next_pkt_q_to_run(ll_event_dispatcher_t *ev_dis) {

    void *obj;

    for (int pri = LL_TASK_PRIORITY_FIRST; pri < LL_TASK_PRIORITY_MAX; pri++) {
        if (rte_ring_dequeue(ev_dis->ready_q[pri], &obj) == 0) {
            return (ll_pkt_q_t *)obj;
        }
    }
    return NULL;
}

/*
 * Called by the dispatcher right after a callback returns.
 * Equivalent of the TASK_PKT_Q_JOB branch of eve_dis_process_task_post_call()
 * in the original: if packets remain, re-schedule the pkt_q at the TAIL of
 * its priority (round robin with other pkt_qs of the same priority).
 */
static void
ll_eve_dis_process_pkt_q_post_call(ll_event_dispatcher_t *ev_dis, ll_pkt_q_t *pkt_q) {

    /* Release ownership: from now on producers may schedule this pkt_q. */
    pkt_q->scheduled.store(false, std::memory_order_seq_cst);

    /*
     * Race being handled here: a producer may have enqueued a packet while
     * the callback was running. Its CAS on `scheduled` failed (flag was
     * true), so it did NOT schedule the pkt_q, relying on us. Hence we must
     * re-check the ring AFTER clearing the flag:
     *   Producer:   enqueue pkt ; FENCE ; CAS scheduled
     *   Dispatcher: scheduled = false ; FENCE ; check ring empty
     * One of the two is guaranteed to see the other, so the packet is never
     * stranded. If both see each other, the CAS makes only one of them win.
     */
    std::atomic_thread_fence(std::memory_order_seq_cst);

    if (!rte_ring_empty(pkt_q->ring)) {
        LL_TRACE("%s : pkt_q %p has more pkts, re-scheduling",
                 ev_dis->name, (void *)pkt_q);
        ll_pkt_q_schedule(ev_dis, pkt_q);
    }
}

/* ========================================================================== */
/*                           pkt_q deletion support                           */
/* ========================================================================== */

/*
 * Remove pkt_q from its ready queue. MUST run on the dispatcher thread, or
 * when no dispatcher thread exists, because it dequeues from the ring and the
 * ring is Single-Consumer.
 *
 * A ring cannot delete from the middle, so we rotate it: pop every element
 * present now and push back everything except pkt_q. O(n) in number of
 * pkt_qs, but this happens only on deletion (control plane), never on the
 * packet path. Producers may push concurrently; that is fine (MP enqueue).
 */
static void
ll_ev_dis_detach_pkt_q(ll_event_dispatcher_t *ev_dis, ll_pkt_q_t *pkt_q) {

    struct rte_ring *rq = ev_dis->ready_q[pkt_q->priority];
    unsigned int n = rte_ring_count(rq);
    void *obj;

    for (unsigned int i = 0; i < n; i++) {
        if (rte_ring_dequeue(rq, &obj) != 0) break;
        if (obj == pkt_q) continue;
        int rc = rte_ring_enqueue(rq, obj);
        assert(rc == 0);
        (void)rc;
    }

    /* Keep it "scheduled" forever so nothing can push it again. */
    pkt_q->scheduled.store(true, std::memory_order_relaxed);

    /* Deleting the pkt_q whose callback is running (from inside that very
     * callback): tell the dispatcher loop not to touch it after return. */
    if (ev_dis->current_pkt_q == pkt_q) {
        ev_dis->current_pkt_q = NULL;
    }
}

/*
 * Dispatcher thread: service a deletion request posted by another thread.
 * Called between callbacks, so no callback is running.
 */
static void
ll_ev_dis_service_del_req(ll_event_dispatcher_t *ev_dis) {

    pthread_mutex_lock(&ev_dis->ev_dis_mutex);
    if (ev_dis->del_req.load()) {
        ll_ev_dis_detach_pkt_q(ev_dis, ev_dis->del_req.load());
        ev_dis->del_req.store(NULL);
        pthread_cond_broadcast(&ev_dis->del_done_cond);
    }
    pthread_mutex_unlock(&ev_dis->ev_dis_mutex);
}

/* ========================================================================== */
/*                          The dispatcher thread                             */
/* ========================================================================== */

static void *
ll_event_dispatcher_thread(void *arg) {

    ll_event_dispatcher_t *ev_dis = (ll_event_dispatcher_t *)arg;
    ll_pkt_q_t *pkt_q;

    while (!ev_dis->stop_req.load(std::memory_order_relaxed)) {

        /* Cheap check first so the mutex is not taken on every iteration.
         * Reading del_req without the lock is a hint only; the real check is
         * done again under the lock inside ll_ev_dis_service_del_req(). */
        if (ev_dis->del_req.load(std::memory_order_acquire)) {
            ll_ev_dis_service_del_req(ev_dis);
        }

        pkt_q = ll_event_dispatcher_get_next_pkt_q_to_run(ev_dis);

        if (!pkt_q) {
            ll_ev_dis_wait_for_work(ev_dis);
            continue;
        }

        ev_dis->current_pkt_q = pkt_q;
        ev_dis->ev_dis_state.store(LL_EV_DIS_TASK_FIN_WAIT, std::memory_order_relaxed);
        gettimeofday(&ev_dis->current_task_start_time, NULL);

        LL_TRACE("%s : invoking callback of pkt_q %p", ev_dis->name, (void *)pkt_q);

        /* Run the application callback. It drains packets using
         * ll_task_get_next_pkt() until NULL or until should_suspend(). */
        pkt_q->cbk(ev_dis, (void *)pkt_q, sizeof(*pkt_q));
        ev_dis->n_task_exec++;

        /* current_pkt_q is NULL if the callback de-initialized its own pkt_q;
         * the pkt_q memory may already be gone, so do not touch it. */
        if (ev_dis->current_pkt_q == NULL) continue;

        pkt_q->no_of_invocations++;
        ev_dis->current_pkt_q = NULL;
        ll_eve_dis_process_pkt_q_post_call(ev_dis, pkt_q);
    }

    /* Exiting: answer any pending deletion so its caller does not hang, then
     * mark the thread gone so future deletions detach directly. */
    pthread_mutex_lock(&ev_dis->ev_dis_mutex);
    if (ev_dis->del_req.load()) {
        ll_ev_dis_detach_pkt_q(ev_dis, ev_dis->del_req.load());
        ev_dis->del_req.store(NULL);
        pthread_cond_broadcast(&ev_dis->del_done_cond);
    }
    ev_dis->thread_running = false;
    ev_dis->ev_dis_state.store(LL_EV_DIS_IDLE, std::memory_order_relaxed);
    pthread_mutex_unlock(&ev_dis->ev_dis_mutex);

    return NULL;
}

/* ========================================================================== */
/*                         Dispatcher public APIs                             */
/* ========================================================================== */

bool
ll_event_dispatcher_init(ll_event_dispatcher_t *ev_dis, const char *name) {

    char ring_name[RTE_RING_NAMESIZE];

    memset((void *)ev_dis, 0, sizeof(*ev_dis));
    strncpy(ev_dis->name, name, sizeof(ev_dis->name) - 1);

    for (int pri = LL_TASK_PRIORITY_FIRST; pri < LL_TASK_PRIORITY_MAX; pri++) {

        snprintf(ring_name, sizeof(ring_name), "llrq_%d_%p", pri, (void *)ev_dis);
        ev_dis->ready_q[pri] = ll_ring_alloc(ring_name, LL_EV_DIS_MAX_PKT_Q,
                                             sizeof(void *));
        if (!ev_dis->ready_q[pri]) {
            for (int j = LL_TASK_PRIORITY_FIRST; j < pri; j++) {
                ll_ring_free(ev_dis->ready_q[j]);
                ev_dis->ready_q[j] = NULL;
            }
            return false;
        }
    }

    ev_dis->ev_dis_state.store(LL_EV_DIS_IDLE);
    pthread_mutex_init(&ev_dis->ev_dis_mutex, NULL);
    pthread_cond_init(&ev_dis->ev_dis_cond_wait, NULL);
    pthread_cond_init(&ev_dis->del_done_cond, NULL);
    pthread_mutex_init(&ev_dis->ctrl_mutex, NULL);
    ev_dis->sleeping.store(false);
    ev_dis->signal_sent_cnt.store(0);
    ev_dis->stop_req.store(false);
    ev_dis->thread_running = false;
    ev_dis->del_req.store(NULL);
    ev_dis->current_pkt_q = NULL;
    return true;
}

static int
ll_event_dispatcher_get_high_perf_core(void) {

    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    return (num_cpus <= 0) ? -1 : num_cpus - 1;
}

void
ll_event_dispatcher_run(ll_event_dispatcher_t *ev_dis, bool pin_to_core, int core_id) {

    pthread_mutex_lock(&ev_dis->ev_dis_mutex);
    if (ev_dis->thread_running) {
        pthread_mutex_unlock(&ev_dis->ev_dis_mutex);
        return;
    }
    ev_dis->stop_req.store(false);
    ev_dis->thread_running = true;
    pthread_mutex_unlock(&ev_dis->ev_dis_mutex);

    /* Joinable (not detached like the original) so that
     * ll_event_dispatcher_stop() can wait for it. */
    if (pthread_create(&ev_dis->thread, NULL, ll_event_dispatcher_thread, ev_dis) != 0) {
        pthread_mutex_lock(&ev_dis->ev_dis_mutex);
        ev_dis->thread_running = false;
        pthread_mutex_unlock(&ev_dis->ev_dis_mutex);
        fprintf(stderr, "%s : failed to create dispatcher thread\n", ev_dis->name);
        return;
    }

    if (pin_to_core) {
        if (core_id < 0) core_id = ll_event_dispatcher_get_high_perf_core();
        if (core_id >= 0) {
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET(core_id, &cpuset);
            if (pthread_setaffinity_np(ev_dis->thread, sizeof(cpuset), &cpuset) != 0) {
                fprintf(stderr, "%s : failed to pin dispatcher to core %d\n",
                        ev_dis->name, core_id);
            }
        }
    }
}

void
ll_event_dispatcher_stop(ll_event_dispatcher_t *ev_dis) {

    pthread_mutex_lock(&ev_dis->ev_dis_mutex);
    if (!ev_dis->thread_running) {
        pthread_mutex_unlock(&ev_dis->ev_dis_mutex);
        return;
    }
    ev_dis->stop_req.store(true);
    pthread_cond_signal(&ev_dis->ev_dis_cond_wait);
    pthread_mutex_unlock(&ev_dis->ev_dis_mutex);

    pthread_join(ev_dis->thread, NULL);
}

void
ll_event_dispatcher_destroy(ll_event_dispatcher_t *ev_dis) {

    ll_event_dispatcher_stop(ev_dis);
    assert(ev_dis->n_pkt_q == 0);

    for (int pri = LL_TASK_PRIORITY_FIRST; pri < LL_TASK_PRIORITY_MAX; pri++) {
        ll_ring_free(ev_dis->ready_q[pri]);
        ev_dis->ready_q[pri] = NULL;
    }
    pthread_mutex_destroy(&ev_dis->ev_dis_mutex);
    pthread_mutex_destroy(&ev_dis->ctrl_mutex);
    pthread_cond_destroy(&ev_dis->ev_dis_cond_wait);
    pthread_cond_destroy(&ev_dis->del_done_cond);
}

bool
ll_event_dispatcher_should_suspend(ll_event_dispatcher_t *ev_dis) {

    struct timeval *start_time = &ev_dis->current_task_start_time;
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    long long msec1 = (((long long)start_time->tv_sec) * 1000) + (start_time->tv_usec / 1000);
    long long msec2 = (((long long)current_time.tv_sec) * 1000) + (current_time.tv_usec / 1000);
    return (msec2 - msec1) >= LL_EVENT_DIS_PREEMPT_INTERVAL_IN_MSEC;
}

ll_pkt_q_t *
ll_eve_dis_get_current_pkt_q(ll_event_dispatcher_t *ev_dis) {

    return ev_dis->current_pkt_q;
}

int
ll_scheduler_task_queue(ll_event_dispatcher_t *ev_dis) {

    int count = 0;

    printf("Event Dispatcher [%s] : state=%s, sleeping=%d, "
           "signals sent=%u recvd=%u, callbacks executed=%lu\n",
           ev_dis->name,
           ev_dis->ev_dis_state.load() == LL_EV_DIS_IDLE ? "IDLE" : "TASK_FIN_WAIT",
           (int)ev_dis->sleeping.load(),
           ev_dis->signal_sent_cnt.load(), ev_dis->signal_recv_cnt,
           (unsigned long)ev_dis->n_task_exec);

    printf("  Ready Queues (pkt_qs waiting to run):\n");
    for (int pri = LL_TASK_PRIORITY_FIRST; pri < LL_TASK_PRIORITY_MAX; pri++) {
        unsigned int n = rte_ring_count(ev_dis->ready_q[pri]);
        if (n) printf("    Priority (%d) : %u pkt_q(s)\n", pri, n);
        count += n;
    }

    printf("  Registered pkt_qs:\n");
    pthread_mutex_lock(&ev_dis->ctrl_mutex);
    for (uint32_t i = 0; i < ev_dis->n_pkt_q; i++) {
        ll_pkt_q_t *q = ev_dis->pkt_q_list[i];
        printf("    [%u] pkt_q=%p pri=%d pkts=%u drops=%u scheduled=%d "
               "invocations=%u dequeued=%lu\n",
               i, (void *)q, q->priority, rte_ring_count(q->ring),
               q->drop_count.load(), (int)q->scheduled.load(),
               q->no_of_invocations, (unsigned long)q->deq_count);
    }
    pthread_mutex_unlock(&ev_dis->ctrl_mutex);

    return count;
}

/* ========================================================================== */
/*                            pkt_q public APIs                               */
/* ========================================================================== */

bool
ll_init_pkt_q(ll_event_dispatcher_t *ev_dis,
              ll_pkt_q_t *pkt_q,
              ll_event_cbk cbk,
              ll_task_priority_t priority) {

    char ring_name[RTE_RING_NAMESIZE];

    if (priority < LL_TASK_PRIORITY_FIRST || priority >= LL_TASK_PRIORITY_MAX) {
        return false;
    }

    snprintf(ring_name, sizeof(ring_name), "llpq_%p", (void *)pkt_q);
    pkt_q->ring = ll_ring_alloc(ring_name, LL_PKT_Q_MAX_QUEUE_SIZE, sizeof(ll_pkt_elem_t));
    if (!pkt_q->ring) return false;

    pkt_q->ev_dis = ev_dis;
    pkt_q->cbk = cbk;
    pkt_q->priority = priority;
    pkt_q->free_cbk = NULL;
    pkt_q->n_inflight_producers.store(0);
    pkt_q->scheduled.store(false);
    pkt_q->drop_count.store(0);
    pkt_q->deq_count = 0;
    pkt_q->no_of_invocations = 0;

    pthread_mutex_lock(&ev_dis->ctrl_mutex);
    if (ev_dis->n_pkt_q >= LL_EV_DIS_MAX_PKT_Q) {
        pthread_mutex_unlock(&ev_dis->ctrl_mutex);
        ll_ring_free(pkt_q->ring);
        pkt_q->ring = NULL;
        return false;
    }
    ev_dis->pkt_q_list[ev_dis->n_pkt_q++] = pkt_q;
    pthread_mutex_unlock(&ev_dis->ctrl_mutex);

    /* Publish last: the release store makes all fields above visible to any
     * producer that observes active == true. */
    pkt_q->active.store(true, std::memory_order_release);
    return true;
}

void
ll_de_init_pkt_q(ll_pkt_q_t *pkt_q) {

    ll_event_dispatcher_t *ev_dis = pkt_q->ev_dis;
    ll_pkt_elem_t elem;

    if (!ev_dis) return;

    /*
     * Step 1 : Fence off producers.
     * Producer:  n_inflight++ ; FENCE ; read active
     * Deleter :  active=false ; FENCE ; read n_inflight
     * Once we see n_inflight == 0 after clearing `active`, every producer
     * either finished, or will see active == false and back off. No producer
     * will touch this pkt_q again.
     */
    pkt_q->active.store(false, std::memory_order_seq_cst);
    while (pkt_q->n_inflight_producers.load(std::memory_order_seq_cst) != 0) {
        rte_pause();
    }

    /*
     * Step 2 : Remove pkt_q from the ready queue. Only the consumer may
     * dequeue from a ready queue, so pick whoever is allowed to do it.
     */
    pthread_mutex_lock(&ev_dis->ev_dis_mutex);

    if (!ev_dis->thread_running ||
        pthread_equal(pthread_self(), ev_dis->thread)) {

        /* No dispatcher thread exists, or we ARE the dispatcher (deleting
         * from inside a callback): detach directly. */
        ll_ev_dis_detach_pkt_q(ev_dis, pkt_q);
    } else {

        /* Ask the dispatcher to do it and wait. One request slot: wait for
         * any other in-progress deletion first. */
        while (ev_dis->del_req.load() != NULL && ev_dis->thread_running) {
            pthread_cond_wait(&ev_dis->del_done_cond, &ev_dis->ev_dis_mutex);
        }

        if (!ev_dis->thread_running) {
            ll_ev_dis_detach_pkt_q(ev_dis, pkt_q);
        } else {
            ev_dis->del_req.store(pkt_q, std::memory_order_release);
            pthread_cond_signal(&ev_dis->ev_dis_cond_wait); /* in case it sleeps */
            while (ev_dis->del_req.load() == pkt_q) {
                pthread_cond_wait(&ev_dis->del_done_cond, &ev_dis->ev_dis_mutex);
            }
        }
    }
    pthread_mutex_unlock(&ev_dis->ev_dis_mutex);

    /* Step 3 : Unregister. */
    pthread_mutex_lock(&ev_dis->ctrl_mutex);
    for (uint32_t i = 0; i < ev_dis->n_pkt_q; i++) {
        if (ev_dis->pkt_q_list[i] == pkt_q) {
            ev_dis->pkt_q_list[i] = ev_dis->pkt_q_list[--ev_dis->n_pkt_q];
            break;
        }
    }
    pthread_mutex_unlock(&ev_dis->ctrl_mutex);

    /* Step 4 : Nobody references the pkt_q any more. Free left-over packets
     * and the ring. */
    while (rte_ring_dequeue_elem(pkt_q->ring, &elem, sizeof(elem)) == 0) {
        if (!elem.pkt) continue;
        if (pkt_q->free_cbk) pkt_q->free_cbk(elem.pkt);
        else free(elem.pkt);
    }
    ll_ring_free(pkt_q->ring);
    pkt_q->ring = NULL;
    pkt_q->ev_dis = NULL;
}

bool
ll_pkt_q_enqueue(ll_event_dispatcher_t *ev_dis,
                 ll_pkt_q_t *pkt_q,
                 char *pkt, uint32_t pkt_size) {

    (void)ev_dis; /* pkt_q->ev_dis is authoritative; kept for API parity */

    /* Announce ourselves before checking `active` (pairs with Step 1 of
     * ll_de_init_pkt_q). */
    pkt_q->n_inflight_producers.fetch_add(1, std::memory_order_seq_cst);

    if (!pkt_q->active.load(std::memory_order_seq_cst)) {
        pkt_q->n_inflight_producers.fetch_sub(1, std::memory_order_release);
        return false;
    }

    ll_pkt_elem_t elem = { pkt, pkt_size, 0 };

    /* O(1), lock-free, multi-producer safe. The 16-byte element is copied
     * into the ring by value: no malloc(). */
    if (rte_ring_enqueue_elem(pkt_q->ring, &elem, sizeof(elem)) != 0) {
        pkt_q->drop_count.fetch_add(1, std::memory_order_relaxed);
        pkt_q->n_inflight_producers.fetch_sub(1, std::memory_order_release);
        return false;
    }

    /* Pairs with the fence in ll_eve_dis_process_pkt_q_post_call(): our
     * packet must be visible before we test-and-set `scheduled`. */
    std::atomic_thread_fence(std::memory_order_seq_cst);

    ll_pkt_q_schedule(pkt_q->ev_dis, pkt_q);

    pkt_q->n_inflight_producers.fetch_sub(1, std::memory_order_release);
    return true;
}

char *
ll_task_get_next_pkt(ll_event_dispatcher_t *ev_dis, uint32_t *pkt_size) {

    ll_pkt_q_t *pkt_q = ev_dis->current_pkt_q;
    ll_pkt_elem_t elem;

    if (!pkt_q) return NULL;

    /* O(1), single-consumer dequeue: no atomic RMW needed at all. */
    if (rte_ring_dequeue_elem(pkt_q->ring, &elem, sizeof(elem)) != 0) {
        return NULL;
    }

    pkt_q->deq_count++;
    if (pkt_size) *pkt_size = elem.pkt_size;
    return elem.pkt;
}

uint32_t
ll_pkt_q_count(ll_pkt_q_t *pkt_q) {

    return rte_ring_count(pkt_q->ring);
}
