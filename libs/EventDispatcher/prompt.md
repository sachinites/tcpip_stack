# Prompt: Implement LockLessEvDis from PubLockLessEvDis.h

Copy everything below the line into an AI coding agent, and attach
`PubLockLessEvDis.h` as the public API contract. The agent must produce a
matching implementation (private header + `.cpp` + build script), not redesign
the API.

---

## Task

Implement a **lock-less Multi-Producer / Single-Consumer (MPSC) Event
Dispatcher** that fully realizes the public API in `PubLockLessEvDis.h`.

Do **not** change, rename, or extend the public API. Application code must
`#include` only `PubLockLessEvDis.h`. Keep struct layouts and internal helpers
in a private header `LockLessEvDis.h` that applications never include.

Deliverables:

| File | Purpose |
|------|---------|
| `LockLessEvDis.h` | Private: full `ll_pkt_q_` / `ll_event_dispatcher_` layouts, `ll_pkt_elem_t` |
| `LockLessEvDis.cpp` | Full implementation of every public symbol |
| `compile_ll.sh` | Build against DPDK `librte_ring` via `pkg-config` (no `rte_eal_init`) |

Language: **C++17**, `std::atomic`, pthreads. Names stay prefixed `ll_` / `LL_`.

---

## Problem this library solves

A control plane has many sources of work (RX, timers, CLI, IPC). Handlers must
not run on arbitrary threads (shared state would need locks). Instead:

> **One dispatcher thread runs all callbacks, one at a time.**

Other threads only hand work over by enqueueing opaque packets into a
**packet queue (pkt_q)**. The dispatcher picks the highest-priority ready
pkt_q and invokes its callback. Application code inside a callback is
serialized and needs no locks.

---

## Architecture (must match)

Two levels of DPDK `rte_ring`, both MPSC (multi-producer, **single** consumer):

```
Producers  --ll_pkt_q_enqueue-->  pkt_q->ring  (elements: {pkt*, size})
                                      |
                    first packet CAS schedule
                                      v
                              ready_q[priority]  (elements: ll_pkt_q_t *)
                                      |
                              dispatcher thread
                                      v
                         pkt_q->cbk(...) drains via ll_task_get_next_pkt
```

Rules:

1. The pkt_q itself is the schedulable entity.
2. **No per-packet malloc** on the hot path. Store `{char *pkt; uint32_t
   pkt_size; uint32_t pad}` (16 bytes) **by value** in the pkt_q ring using
   `rte_ring_*_elem`.
3. Enqueue / dequeue of packets and ready pointers must be **O(1)**.
4. Mutexes are **not** on the packet hot path. Use them only for sleep/wake
   and rare control-plane ops (register / delete pkt_q).
5. When idle, the dispatcher **sleeps** on a condition variable; producers
   wake it. Under load it must not spin forever.
6. Same priority levels and order as `ll_task_priority_t` in the public
   header (CRITICAL first … VERY_LOW last). Same priority = **round-robin**
   (re-schedule at ready-queue **tail**).
7. Scheduling is **cooperative**. Never preempt a running callback.
8. Opaque handles: apps allocate via `ll_event_dispatcher_create` /
   `ll_pkt_q_create` only (heap). Destroy then free pkt_qs; destroy
   dispatcher last.

---

## DPDK ring requirements (critical)

- Do **not** call `rte_eal_init()` or `rte_ring_create()`.
- Allocate rings with `posix_memalign(..., RTE_CACHE_LINE_SIZE, ...)` +
  `rte_ring_init()`.
- Capacity: use `RING_F_EXACT_SZ` so capacity is exactly
  `LL_PKT_Q_MAX_QUEUE_SIZE` (pkt_q) or `LL_EV_DIS_MAX_PKT_Q` (ready queues).
  Size memory with `rte_align32pow2(capacity + 1)` and
  `rte_ring_get_memsize_elem`.
- Flags: `RING_F_SC_DEQ | RING_F_EXACT_SZ` plus producer sync
  **`RING_F_MP_RTS_ENQ` by default** (Relaxed Tail Sync). Classic MP (`0`)
  can livelock under preemptible pthreads when producers > CPUs. Make the
  flag overridable via `-DLL_RING_PROD_SYNC_FLAG=...`.
- Ready queues hold `void *` / `ll_pkt_q_t *`. Packet rings hold
  `ll_pkt_elem_t` via elem APIs.
- **C++ / DPDK 26.x include order:** include `<rte_bitops.h>` in C++ first,
  then wrap `<rte_ring.h>`, `<rte_ring_elem.h>`, `<rte_pause.h>` in
  `extern "C"`. Otherwise bitops overloads break or
  `rte_ring_get_memsize_elem` gets wrong linkage.

Link: `pkg-config --cflags libdpdk` and `-lrte_ring -lrte_eal -lrte_log -lpthread`.

---

## Private data structures (define in LockLessEvDis.h)

Group fields by who writes them.

### `ll_pkt_elem_t`

```c
typedef struct ll_pkt_elem_ {
    char *pkt;
    uint32_t pkt_size;
    uint32_t pad;   /* make sizeof == 16 (multiple of 4 for elem rings) */
} ll_pkt_elem_t;
```

### `struct ll_pkt_q_`

| Field | Role |
|-------|------|
| `ring` | MPSC elem ring of `ll_pkt_elem_t` |
| `ev_dis` | owner dispatcher |
| `cbk` | NULL ⇒ **passive** queue: never schedule |
| `priority` | which `ready_q` |
| `free_cbk` | free leftovers in destroy; NULL ⇒ leave to app |
| `active` | false once destroy started; producers must back off |
| `n_inflight_producers` | count of threads inside enqueue |
| `scheduled` | **key flag** — see below |
| `drop_count` | rejected enqueues (ring full) |
| `deq_count`, `no_of_invocations` | dispatcher-thread stats |

### `struct ll_event_dispatcher_`

| Field | Role |
|-------|------|
| `name[32]`, `core_id` | label + CPU affinity |
| `ready_q[LL_TASK_PRIORITY_MAX]` | one MPSC ring of `pkt_q*` per priority |
| `ev_dis_state` | IDLE / TASK_FIN_WAIT |
| `ev_dis_mutex`, `ev_dis_cond_wait`, `sleeping` | Wait/Signal |
| `signal_sent_cnt`, `signal_recv_cnt` | diagnostics |
| `thread`, `thread_running`, `stop_req` | consumer lifecycle |
| `ctrl_mutex`, `pkt_q_list[]`, `n_pkt_q` | registry (≤ MAX) |
| `del_req`, `del_done_cond` | async delete from non-dispatcher threads |
| `current_pkt_q`, `current_task_start_time`, `n_task_exec` | running callback |
| `app_data` | optional cookie |

---

## Core protocol: `scheduled` flag

`scheduled == true` means: this pkt_q’s pointer is in a ready queue **or**
its callback is running.

**Rule:** only the thread that CAS-es `scheduled` false→true may
`rte_ring_enqueue` the pkt_q into `ready_q[priority]`.

Invariant: each pkt_q appears **at most once** across all ready queues ⇒
ready queue size `LL_EV_DIS_MAX_PKT_Q` ⇒ ready enqueue **never fails**.

Passive queues (`cbk == NULL`): schedule is a no-op.

---

## Producer: `ll_pkt_q_enqueue`

Exact order (store-buffering safe):

1. `n_inflight_producers++` (seq_cst), then if `!active` decrement and return false.
2. `rte_ring_enqueue_elem({pkt, size})`. On full: `drop_count++`, decrement
   inflight, return false.
3. `atomic_thread_fence(seq_cst)`.
4. `ll_pkt_q_schedule`: CAS `scheduled` false→true; if won, push to
   `ready_q[pri]` and wakeup.
5. `n_inflight_producers--`.

On success the library owns `pkt`; on false the caller still owns it.

---

## Wait / Signal (no lost wake-ups)

**Dispatcher wait** (only when no ready work):

```
lock(mutex);
sleeping = true;
fence(seq_cst);
while (!stop && !del_req && all ready_q empty)
    cond_wait(cond, mutex);
sleeping = false;
unlock(mutex);
```

**Producer wakeup** (only after pushing into a ready queue):

```
fence(seq_cst);
if (sleeping) { lock(mutex); cond_signal(cond); unlock(mutex); }
```

Same Dekker / store-buffering pattern as re-schedule: at least one side
sees the other. Holding the mutex from `sleeping=true` until `cond_wait`
prevents signaling before the waiter is parked. Extra signals are harmless.

---

## Consumer thread loop

```
while (!stop_req) {
    if (del_req) service_del_req();          // between callbacks
    pkt_q = dequeue highest non-empty ready_q;  // scan pri 0..MAX-1
    if (!pkt_q) { wait_for_work(); continue; }

    current_pkt_q = pkt_q;
    record start time; state = TASK_FIN_WAIT;
    pkt_q->cbk(ev_dis, pkt_q, sizeof(*pkt_q));
    n_task_exec++;

    if (current_pkt_q == NULL) continue;   // callback destroyed itself
    current_pkt_q = NULL;
    no_of_invocations++;
    post_call(pkt_q);                      // see below
}
```

Pin the thread with `pthread_setaffinity_np` to `core_id`.

### Post-call re-schedule (no stranded packets)

```
scheduled = false;          // seq_cst store
fence(seq_cst);
if (!rte_ring_empty(pkt_q->ring))
    ll_pkt_q_schedule(...); // CAS + push
```

Pairs with producer’s enqueue→fence→CAS. Without both fences, store
buffering can leave a packet forever unscheduled.

`ll_event_dispatcher_should_suspend`: true if
`(now - current_task_start_time) >= LL_EVENT_DIS_PREEMPT_INTERVAL_IN_MSEC`.

`ll_task_get_next_pkt`: dequeue one elem from `current_pkt_q->ring` only;
bump `deq_count`.

---

## Safe destroy: `ll_pkt_q_destroy`

After return, the handle is inert but still valid until `ll_pkt_q_free`.
No thread may touch the object after free.

**Step 1 — fence producers (store-buffering):**

```
active = false; fence/seq_cst;
while (n_inflight_producers != 0) rte_pause();
```

**Step 2 — detach from ready queue** (SC dequeue only):

Rotate ready_q[priority]: dequeue all current entries, re-enqueue all except
this pkt_q. Then force `scheduled = true` so nothing re-pushes it.

Who runs detach:

- No consumer thread, **or** caller **is** the dispatcher thread → detach
  directly under `ev_dis_mutex`. If destroying the currently running pkt_q,
  set `current_pkt_q = NULL`.
- Else: wait until `del_req` free, store `del_req = pkt_q`, signal wait
  cond, wait on `del_done_cond` until cleared. Dispatcher services between
  callbacks.

**Step 3:** unregister from `pkt_q_list` under `ctrl_mutex`.

**Step 4:** drain leftover ring elems; call `free_cbk` if set; free ring;
clear `ev_dis` / `ring`.

`ll_pkt_q_create` failure paths: if registry full or ring alloc fails,
free any partial allocation and return NULL.

---

## Public API behavior checklist

Implement exactly the symbols in `PubLockLessEvDis.h`:

- `ll_event_dispatcher_create / run / stop / destroy`
- `ll_event_dispatcher_should_suspend`, `ll_eve_dis_get_current_pkt_q`
- `ll_scheduler_task_queue` (debug print of state + queues + registered pkt_qs)
- `ll_pkt_q_create / destroy / free`
- `ll_pkt_q_enqueue`, `ll_task_get_next_pkt`
- `ll_pkt_q_count`, `ll_ptk_q_drop_count`

Destroy dispatcher only after all pkt_qs are destroyed and freed. Destroy
stops/joins the thread if still running.

---

## Correctness properties to preserve

1. **Zero packet loss** when producers retry on full (drop_count == retries).
2. **Per-producer FIFO** within each pkt_q ring.
3. **Priority order** independent of enqueue order (CRITICAL before LOW).
4. **Round-robin** among same-priority ready pkt_qs.
5. **No stranded packets** after callback returns under concurrent enqueue.
6. **No lost wake-ups** when dispatcher goes idle.
7. **Destroy under load**: every accepted packet is either consumed by the
   callback or freed by destroy’s `free_fn` exactly once.
8. **Self-delete** from inside own callback must not UAF (null
   `current_pkt_q`, skip post_call).
9. **Passive** (`cbk == NULL`) queues accept packets but never enter ready_q.

---

## Build

```bash
# compile_ll.sh sketch
g++ -g -O2 -Wall -Wextra -std=c++17 $(pkg-config --cflags libdpdk) \
    -c LockLessEvDis.cpp
# link with -lrte_ring -lrte_eal -lrte_log -lpthread
```

Optional: `-DLL_EV_DIS_DEBUG` for scheduling traces (off by default — printf
locks destroy the lock-less hot path).

---

## Out of scope / non-goals

- Do not reintroduce spinlocks or malloc on the enqueue/dequeue path.
- Do not require hugepages / EAL init.
- Do not expose private fields through the public header.
- Do not change public function signatures or names.

---

## Suggested implementation order

1. Private structs + ring alloc/free helpers.
2. Dispatcher create/run/stop/destroy + empty consumer loop (wait/signal).
3. pkt_q create/destroy/free + registry.
4. enqueue + schedule CAS + wakeup.
5. drain + post_call re-schedule + should_suspend.
6. Async delete path (`del_req`).
7. Debug dump + compile script.
8. Self-test mentally against the correctness list above; fix fence bugs
   first if anything strands work or loses wake-ups.

When done, `PubLockLessEvDis.h` must remain the sole application include,
and every public API must behave as documented in that header.
