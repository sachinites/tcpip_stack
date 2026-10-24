/*
 * =====================================================================================
 *
 *       Filename:  LockLessEvDis.h
 *
 *    Description:  PRIVATE / INTERNAL header for the lock-less Event Dispatcher.
 *
 *                  Application developers must NOT include this file.
 *                  Include PubLockLessEvDis.h instead.
 *
 * =====================================================================================
 */

#ifndef LOCK_LESS_EV_DIS_H
#define LOCK_LESS_EV_DIS_H

#include <pthread.h>
#include <sys/time.h>
#include <atomic>

#include "PubLockLessEvDis.h"

#define LL_EV_DIS_NAME_LEN 32

typedef enum {

    LL_EV_DIS_IDLE,
    LL_EV_DIS_TASK_FIN_WAIT,
} LL_EV_DISPATCHER_STATE;

/* Defined by DPDK. Only this library needs the full type. */
struct rte_ring;

/*
 * One element stored (by value) inside a pkt_q's rte_ring.
 * rte_ring element size must be a multiple of 4 bytes: this is 16.
 */
typedef struct ll_pkt_elem_ {

    char *pkt;
    uint32_t pkt_size;
    uint32_t pad;
} ll_pkt_elem_t;

/*
 * Packet queue — private layout.
 * Fields are grouped by who writes them.
 */
struct ll_pkt_q_ {

    /* ---------------- Init-only ---------------- */
    struct rte_ring *ring;
    ll_event_dispatcher_t *ev_dis;
    ll_event_cbk cbk;
    ll_task_priority_t priority;
    void (*free_cbk)(void *);

    /* ---------------- Shared: producers + dispatcher ---------------- */
    std::atomic<bool> active;
    std::atomic<uint32_t> n_inflight_producers;
    std::atomic<bool> scheduled;
    std::atomic<uint32_t> drop_count;

    /* ---------------- Dispatcher-thread only ---------------- */
    uint64_t deq_count;
    uint32_t no_of_invocations;
};

struct ll_event_dispatcher_ {

    char name[LL_EV_DIS_NAME_LEN];

    struct rte_ring *ready_q[LL_TASK_PRIORITY_MAX];

    std::atomic<LL_EV_DISPATCHER_STATE> ev_dis_state;

    pthread_mutex_t ev_dis_mutex;
    pthread_cond_t ev_dis_cond_wait;
    std::atomic<bool> sleeping;
    std::atomic<uint32_t> signal_sent_cnt;
    uint32_t signal_recv_cnt;

    pthread_t thread;
    bool thread_running;
    std::atomic<bool> stop_req;
    int core_id;

    pthread_mutex_t ctrl_mutex;
    ll_pkt_q_t *pkt_q_list[LL_EV_DIS_MAX_PKT_Q];
    uint32_t n_pkt_q;

    std::atomic<ll_pkt_q_t *> del_req;
    pthread_cond_t del_done_cond;

    ll_pkt_q_t *current_pkt_q;
    struct timeval current_task_start_time;
    uint64_t n_task_exec;

    void *app_data;
};

#endif /* LOCK_LESS_EV_DIS_H */
