/*
 * =====================================================================================
 *
 *       Filename:  LockLessEvDis.h
 *
 *    Description:  Lock-less (DPDK rte_ring based) re-implementation of the
 *                  packet-queue part of the Event Dispatcher
 *                  (see event_dispatcher.h for the original design).
 *
 *                  Read LockLessEvDis_Design.md in this directory first; it
 *                  explains every data structure and protocol used here.
 *
 *       Compiler:  g++ (C++17), needs DPDK headers (pkg-config libdpdk)
 *
 * =====================================================================================
 */

/*
 * What is the same as the original Event Dispatcher (base design retained)
 * --------------------------------------------------------------------------
 *  - ONE dispatcher thread (the consumer) runs ALL callbacks, one at a time.
 *    Application code inside a callback is therefore serialized and needs
 *    no locks, exactly as before.
 *  - Applications create packet queues (pkt_q), register a callback for each,
 *    and any thread may enqueue "packets" (opaque pointers + size) into them.
 *  - When a pkt_q has packets, it is placed on a per-priority ready queue.
 *    The dispatcher always serves the highest priority ready queue first and
 *    is round-robin among pkt_qs of the same priority.
 *  - Inside the callback, the application drains packets using
 *    ll_task_get_next_pkt() and may voluntarily yield using
 *    ll_event_dispatcher_should_suspend().
 *  - When there is no work, the dispatcher sleeps on a condition variable
 *    (Wait) and producers wake it up (Signal).
 *
 * What is different
 * --------------------------------------------------------------------------
 *  - Packet queues and ready queues are DPDK rte_rings configured as
 *    Multi-Producer / Single-Consumer (MPSC). Enqueue and dequeue are O(1),
 *    lock-free, and need no per-packet malloc()/free().
 *  - There is no task_t. The pkt_q itself is the schedulable entity.
 *  - The task_create_* family of APIs is removed; only pkt_q APIs remain.
 *  - The mutex is NOT taken on the fast path. It is used only to put the
 *    dispatcher to sleep / wake it up, and for rare control-plane operations
 *    (pkt_q registration and deletion).
 *
 * All public APIs are prefixed with ll_ and all public types / constants with
 * ll_ / LL_, so this header can be included together with event_dispatcher.h
 * while an application migrates from one to the other.
 */

#ifndef LOCK_LESS_EV_DIS_H
#define LOCK_LESS_EV_DIS_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/time.h>
#include <atomic>

/* Defined by DPDK (rte_ring_core.h). Only the .cpp file needs the full type. */
struct rte_ring;

#define LL_EV_DIS_NAME_LEN 32

/* Max packets a single pkt_q can hold. Same value as PKT_Q_MAX_QUEUE_SIZE in
 * the original. Enqueue beyond this fails and the drop counter increments. */
#define LL_PKT_Q_MAX_QUEUE_SIZE 500

/* Max pkt_qs that can be registered with ONE dispatcher. Each ready queue is
 * sized to this value; since a pkt_q can sit in at most one ready queue at a
 * time, a ready-queue enqueue can never fail (see design doc, "Invariant"). */
#define LL_EV_DIS_MAX_PKT_Q 128

/* A callback running longer than this is asked to yield via
 * ll_event_dispatcher_should_suspend() */
#define LL_EVENT_DIS_PREEMPT_INTERVAL_IN_MSEC 500

typedef struct ll_event_dispatcher_ ll_event_dispatcher_t;
typedef struct ll_pkt_q_ ll_pkt_q_t;

/*
 * Callback invoked by the dispatcher thread when a pkt_q has packets.
 *   arg1 : the dispatcher
 *   arg2 : the ll_pkt_q_t * which became ready
 *   arg3 : sizeof(ll_pkt_q_t)
 * Same shape as event_cbk in the original, so existing callbacks port with
 * only a type change.
 */
typedef void (*ll_event_cbk)(ll_event_dispatcher_t *, void *, uint32_t);

/* Same priority levels (and aliases) as task_priority_t in the original.
 * Lower numeric value == higher priority. */
typedef enum {

    LL_TASK_PRIORITY_FIRST,

    LL_TASK_PRIORITY_CRITICAL = LL_TASK_PRIORITY_FIRST,
    LL_TASK_PRIORITY_CP_TO_DP = LL_TASK_PRIORITY_CRITICAL,
    LL_TASK_PRIORITY_OPERATIONAL_CLI = LL_TASK_PRIORITY_CRITICAL,

    LL_TASK_PRIORITY_HIGH,
    LL_TASK_PRIORITY_PKT_PROCESSING = LL_TASK_PRIORITY_HIGH,
    LL_TASK_PRIORITY_TIMERS_CBK = LL_TASK_PRIORITY_HIGH,

    LL_TASK_PRIORITY_MEDIUM,
    LL_TASK_PRIORITY_COMPUTE = LL_TASK_PRIORITY_MEDIUM,

    LL_TASK_PRIORITY_LOW_MEDIUM,
    LL_TASK_PRIORITY_COMPUTE_LOW = LL_TASK_PRIORITY_LOW_MEDIUM,

    LL_TASK_PRIORITY_LOW,
    LL_TASK_PRIORITY_CONFIG_CLI = LL_TASK_PRIORITY_LOW,

    LL_TASK_PRIORITY_VERY_LOW,
    LL_TASK_PRIORITY_GARBAGE_COLLECTOR = LL_TASK_PRIORITY_VERY_LOW,

    LL_TASK_PRIORITY_MAX

} ll_task_priority_t;

typedef enum {

    LL_EV_DIS_IDLE,          /* Sleeping (or about to) on the condition variable */
    LL_EV_DIS_TASK_FIN_WAIT, /* Running a callback, waiting for it to finish */
} LL_EV_DISPATCHER_STATE;

/*
 * One element stored (by value) inside a pkt_q's rte_ring. Storing the
 * element by value is what removes the per-packet malloc() of the original
 * (which allocated a pkt_t + glthread node for every enqueue).
 * rte_ring element size must be a multiple of 4 bytes: this is 16.
 */
typedef struct ll_pkt_elem_ {

    char *pkt;
    uint32_t pkt_size;
    uint32_t pad;
} ll_pkt_elem_t;

/*
 * Packet queue.
 *
 * Fields are grouped by who writes them. "Init-only" fields are written
 * before the pkt_q is published to other threads and never change afterwards,
 * so they can be read without synchronization.
 */
struct ll_pkt_q_ {

    /* ---------------- Init-only ---------------- */
    struct rte_ring *ring;          /* MPSC ring of ll_pkt_elem_t */
    ll_event_dispatcher_t *ev_dis;  /* Owner dispatcher */
    ll_event_cbk cbk;               /* NULL => passive queue, never scheduled */
    ll_task_priority_t priority;    /* Which ready queue this pkt_q goes to */
    void (*free_cbk)(void *);       /* Frees left-over pkts in ll_de_init_pkt_q().
                                       NULL => leftover user data is not freed */

    /* ---------------- Shared: producers + dispatcher ---------------- */

    /* true  => pkt_q is accepting packets.
     * false => ll_de_init_pkt_q() has started; producers must back off. */
    std::atomic<bool> active;

    /* Number of producers currently inside ll_pkt_q_enqueue() for this pkt_q.
     * ll_de_init_pkt_q() waits for this to reach zero, so nobody touches the
     * pkt_q after it is torn down. */
    std::atomic<uint32_t> n_inflight_producers;

    /* THE key flag that replaces "is task->glue linked in a list?" of the
     * original. true => this pkt_q's pointer is in a ready queue OR its
     * callback is running right now. Whoever flips it false->true (CAS) is
     * the only one allowed to put the pkt_q into a ready queue. This
     * guarantees a pkt_q appears at most once across all ready queues. */
    std::atomic<bool> scheduled;

    std::atomic<uint32_t> drop_count;   /* Enqueues rejected because ring full */

    /* ---------------- Dispatcher-thread only ---------------- */
    uint64_t deq_count;                 /* Packets handed to the application */
    uint32_t no_of_invocations;         /* Times the callback was invoked */
};

struct ll_event_dispatcher_ {

    char name[LL_EV_DIS_NAME_LEN];

    /* One MPSC ring of (ll_pkt_q_t *) per priority level. Producers push a
     * pkt_q pointer at the tail, the dispatcher pops from the head: O(1). */
    struct rte_ring *ready_q[LL_TASK_PRIORITY_MAX];

    std::atomic<LL_EV_DISPATCHER_STATE> ev_dis_state;

    /* ---------- Wait / Signal ---------- */
    pthread_mutex_t ev_dis_mutex;      /* Guards the sleep/wake handshake + del_req */
    pthread_cond_t ev_dis_cond_wait;   /* Dispatcher sleeps here when no work */
    std::atomic<bool> sleeping;        /* Dispatcher is (about to be) in cond_wait.
                                          Producers take the mutex ONLY if true. */
    std::atomic<uint32_t> signal_sent_cnt;
    uint32_t signal_recv_cnt;          /* Dispatcher-thread only */

    /* ---------- Dispatcher thread life cycle ---------- */
    pthread_t thread;
    bool thread_running;               /* Protected by ev_dis_mutex */
    std::atomic<bool> stop_req;
    int core_id;                       /* CPU the dispatcher thread is pinned to */

    /* ---------- Control plane: pkt_q registry and deletion ---------- */
    pthread_mutex_t ctrl_mutex;        /* Guards pkt_q_list / n_pkt_q only */
    ll_pkt_q_t *pkt_q_list[LL_EV_DIS_MAX_PKT_Q];
    uint32_t n_pkt_q;

    /* A non-dispatcher thread deleting a pkt_q posts it here and waits on
     * del_done_cond until the dispatcher has removed it from the ready
     * queue. Both are written under ev_dis_mutex; del_req is atomic because
     * the dispatcher peeks at it without the mutex on every loop iteration. */
    std::atomic<ll_pkt_q_t *> del_req;
    pthread_cond_t del_done_cond;

    /* ---------- Dispatcher-thread only ---------- */
    ll_pkt_q_t *current_pkt_q;         /* pkt_q whose callback is running */
    struct timeval current_task_start_time;
    uint64_t n_task_exec;

    /* Some optional app data */
    void *app_data;
};

/* ============================ Public APIs ============================ */

/* Initialize a dispatcher. Must be called once before anything else.
 * core_id : CPU the dispatcher thread will be pinned to when started
 *           (default 0).
 * Returns false if memory for the ready queues could not be allocated. */
bool
ll_event_dispatcher_init(ll_event_dispatcher_t *ev_dis, const char *name,
                         int core_id = 0);

/* Start the dispatcher (consumer) thread. The thread is pinned to the
 * core_id passed to ll_event_dispatcher_init(). */
void
ll_event_dispatcher_run(ll_event_dispatcher_t *ev_dis);

/* Stop and join the dispatcher thread. Packets still queued are kept. */
void
ll_event_dispatcher_stop(ll_event_dispatcher_t *ev_dis);

/* Release the dispatcher's ready queues. All pkt_qs must have been
 * de-initialized and the dispatcher stopped. */
void
ll_event_dispatcher_destroy(ll_event_dispatcher_t *ev_dis);

/* To be called from inside a callback: true if the callback has been running
 * for longer than LL_EVENT_DIS_PREEMPT_INTERVAL_IN_MSEC and should return,
 * leaving remaining packets for later (the pkt_q is re-scheduled at the
 * tail of its priority, giving other pkt_qs a chance). */
bool
ll_event_dispatcher_should_suspend(ll_event_dispatcher_t *ev_dis);

/* pkt_q whose callback is currently executing (NULL if none). */
ll_pkt_q_t *
ll_eve_dis_get_current_pkt_q(ll_event_dispatcher_t *ev_dis);

/* Debug: print every registered pkt_q and every ready queue.
 * Returns the number of pkt_qs currently waiting in ready queues. */
int
ll_scheduler_task_queue(ll_event_dispatcher_t *ev_dis);

/* Create a pkt_q and register it with ev_dis.
 * priority defaults to LL_TASK_PRIORITY_PKT_PROCESSING, same as the original.
 * free_fn : frees left-over user data in ll_de_init_pkt_q(); NULL => not freed
 *           (application retains ownership).
 * cbk == NULL creates a passive queue which is never scheduled.
 * Returns false if the ring cannot be allocated or the dispatcher already has
 * LL_EV_DIS_MAX_PKT_Q pkt_qs. */
bool
ll_init_pkt_q(ll_event_dispatcher_t *ev_dis,
              ll_pkt_q_t *pkt_q,
              ll_event_cbk cbk,
              ll_task_priority_t priority = LL_TASK_PRIORITY_PKT_PROCESSING,
              void (*free_fn)(void *) = NULL);

/* Tear down a pkt_q. Safe to call from any thread, including from inside a
 * callback (even the pkt_q's own callback), while producers are still
 * enqueueing (their enqueues start failing). Left-over packets are freed via
 * pkt_q->free_cbk only; if free_cbk is NULL they are not freed. */
void
ll_de_init_pkt_q(ll_pkt_q_t *pkt_q);

/* PRODUCER API: callable concurrently from any number of threads.
 * Lock-free, O(1). Returns false (and the caller still owns pkt) if the
 * pkt_q is full or being deleted. */
bool
ll_pkt_q_enqueue(ll_event_dispatcher_t *ev_dis,
                 ll_pkt_q_t *pkt_q,
                 char *pkt, uint32_t pkt_size);

/* CONSUMER API: call ONLY from inside the pkt_q's callback (i.e. on the
 * dispatcher thread). Returns the next packet of the current pkt_q, or NULL
 * if it is empty. O(1). */
char *
ll_task_get_next_pkt(ll_event_dispatcher_t *ev_dis, uint32_t *pkt_size);

/* Number of packets currently sitting in the pkt_q (approximate if producers
 * are active at the same time). */
uint32_t
ll_pkt_q_count(ll_pkt_q_t *pkt_q);

static inline uint32_t
ll_ptk_q_drop_count(ll_pkt_q_t *pkt_q) {

    return pkt_q->drop_count.load(std::memory_order_relaxed);
}

#endif /* LOCK_LESS_EV_DIS_H */
