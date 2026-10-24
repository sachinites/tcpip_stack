/*
 * =====================================================================================
 *
 *       Filename:  PubLockLessEvDis.h
 *
 *    Description:  PUBLIC API for the lock-less (DPDK rte_ring based) Event
 *                  Dispatcher. Application developers must include ONLY this
 *                  header.
 *
 *                  ll_event_dispatcher_t and ll_pkt_q_t are opaque. Allocate
 *                  them only via the create APIs below.
 *
 *       Compiler:  g++ (C++17)
 *
 * =====================================================================================
 */

#ifndef PUB_LOCK_LESS_EV_DIS_H
#define PUB_LOCK_LESS_EV_DIS_H

#include <stdint.h>
#include <stdbool.h>

/* Max packets one pkt_q can hold. Enqueue beyond this fails and increments
 * the drop counter. */
#define LL_PKT_Q_MAX_QUEUE_SIZE 500

/* Max pkt_qs that may be registered with one dispatcher at a time. */
#define LL_EV_DIS_MAX_PKT_Q 128

/* Soft preempt: a callback that has run longer than this (ms) should return
 * when ll_event_dispatcher_should_suspend() is true, so other pkt_qs run. */
#define LL_EVENT_DIS_PREEMPT_INTERVAL_IN_MSEC 500

/* Opaque dispatcher: single consumer thread that runs all callbacks. */
typedef struct ll_event_dispatcher_ ll_event_dispatcher_t;

/* Opaque packet queue: producers enqueue work; the dispatcher drains it. */
typedef struct ll_pkt_q_ ll_pkt_q_t;

/*
 * Application callback for a ready pkt_q. Runs only on the dispatcher thread.
 *   arg1 : dispatcher
 *   arg2 : the ll_pkt_q_t * that became ready
 *   arg3 : opaque size token (API parity with the original event dispatcher)
 * Drain packets with ll_task_get_next_pkt() until NULL or should_suspend().
 */
typedef void (*ll_event_cbk)(ll_event_dispatcher_t *, void *, uint32_t);

/*
 * Scheduling priority for a pkt_q. Lower numeric value = higher priority.
 * Named aliases map common control-plane work to a level.
 */
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

/* ============================ Dispatcher ============================ */

/*
 * Allocate and initialize a dispatcher.
 * name    : short label for debug prints
 * core_id : CPU the consumer thread will be pinned to (default 0)
 * Returns NULL on allocation / ring-setup failure.
 */
ll_event_dispatcher_t *
ll_event_dispatcher_create(const char *name, int core_id = 0);

/*
 * Start the dispatcher consumer thread (pinned to core_id from create).
 * Safe to call once; subsequent calls are no-ops while already running.
 */
void
ll_event_dispatcher_run(ll_event_dispatcher_t *ev_dis);

/*
 * Ask the consumer thread to exit and join it.
 * Packets still sitting in pkt_qs are left as-is until those queues are
 * destroyed.
 */
void
ll_event_dispatcher_stop(ll_event_dispatcher_t *ev_dis);

/*
 * Stop the consumer (if still running), free ready queues, and release the
 * dispatcher. All pkt_qs must already have been destroyed and freed.
 */
void
ll_event_dispatcher_destroy(ll_event_dispatcher_t *ev_dis);

/*
 * Cooperative yield hint for use inside a callback.
 * Returns true when this callback has run longer than
 * LL_EVENT_DIS_PREEMPT_INTERVAL_IN_MSEC; the callback should return so the
 * dispatcher can re-schedule remaining work and serve other pkt_qs.
 */
bool
ll_event_dispatcher_should_suspend(ll_event_dispatcher_t *ev_dis);

/*
 * pkt_q whose callback is running right now (NULL if none).
 * Useful when a callback needs its own handle (e.g. self-delete).
 */
ll_pkt_q_t *
ll_eve_dis_get_current_pkt_q(ll_event_dispatcher_t *ev_dis);

/*
 * Debug dump: print dispatcher state, ready queues, and every registered
 * pkt_q. Returns how many pkt_qs are currently waiting in ready queues.
 */
int
ll_scheduler_task_queue(ll_event_dispatcher_t *ev_dis);

/* ============================ Packet queue ============================ */

/*
 * Allocate a pkt_q, register it with ev_dis, and optionally set a free
 * function for leftover packets when the queue is destroyed.
 * cbk      : callback when packets are ready; NULL = passive (never scheduled)
 * priority : which ready list this queue joins (default PKT_PROCESSING)
 * free_fn  : called on leftover user payloads in ll_pkt_q_destroy(); NULL =
 *            application keeps ownership of leftovers
 * Returns NULL if the ring cannot be allocated or LL_EV_DIS_MAX_PKT_Q is full.
 */
ll_pkt_q_t *
ll_pkt_q_create(ll_event_dispatcher_t *ev_dis,
                ll_event_cbk cbk,
                ll_task_priority_t priority = LL_TASK_PRIORITY_PKT_PROCESSING,
                void (*free_fn)(void *) = NULL);

/*
 * Tear down a pkt_q while producers may still race enqueue.
 * Stops new accepts, waits for in-flight producers, detaches from ready
 * queues, and frees leftover packets via free_fn from create (if any).
 * The handle stays valid but inert until ll_pkt_q_free().
 */
void
ll_pkt_q_destroy(ll_pkt_q_t *pkt_q);

/*
 * Free memory of a pkt_q from ll_pkt_q_create().
 * Call after ll_pkt_q_destroy(). No thread may touch pkt_q afterwards.
 */
void
ll_pkt_q_free(ll_pkt_q_t *pkt_q);

/*
 * PRODUCER API: enqueue a packet from any thread (lock-free, O(1)).
 * On success ownership of pkt moves to the dispatcher / callback.
 * Returns false if the queue is full or destroyed (caller still owns pkt).
 */
bool
ll_pkt_q_enqueue(ll_event_dispatcher_t *ev_dis,
                 ll_pkt_q_t *pkt_q,
                 char *pkt, uint32_t pkt_size);

/*
 * CONSUMER API: next packet of the pkt_q currently being served.
 * Call only from inside that pkt_q's callback (dispatcher thread).
 * Returns NULL when the queue is empty. Writes size into *pkt_size if non-NULL.
 */
char *
ll_task_get_next_pkt(ll_event_dispatcher_t *ev_dis, uint32_t *pkt_size);

/*
 * Approximate number of packets currently buffered in the pkt_q
 * (may race with concurrent producers).
 */
uint32_t
ll_pkt_q_count(ll_pkt_q_t *pkt_q);

/*
 * Number of enqueues rejected because the pkt_q was full (cumulative).
 */
uint32_t
ll_ptk_q_drop_count(ll_pkt_q_t *pkt_q);

#endif /* PUB_LOCK_LESS_EV_DIS_H */
