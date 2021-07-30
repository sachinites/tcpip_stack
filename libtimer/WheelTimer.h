#ifndef __WHEEL_TIMER__
#define __WHEEL_TIMER__

#include <pthread.h>
#include "timerlib.h"
#include <stdint.h>
#include "../gluethread/glthread.h"

typedef enum {

	TIMER_SECONDS,
	TIMER_MILLI_SECONDS
} timer_resolution_t;

typedef struct _wheel_timer_elem_t wheel_timer_elem_t;
typedef void (*app_call_back)(void *arg, uint32_t sizeof_arg);
typedef struct _wheel_timer_t wheel_timer_t;

typedef struct slotlist_{
    glthread_t slots;
    pthread_mutex_t slot_mutex;
}slotlist_t;

typedef enum{

    WTELEM_CREATE,
    WTELEM_RESCHED,
    WTELEM_DELETE,
    WTELEM_SCHEDULED,
    WTELEM_UNKNOWN
} wt_opcode_t;

struct _wheel_timer_elem_t{
    
    wt_opcode_t opcode;
	int time_interval;
    int new_time_interval;
	int execute_cycle_no;
    int slot_no;
	app_call_back app_callback;
	void *arg;
	int arg_size;
	char is_recurrence;
    glthread_t glue;
    slotlist_t *slotlist_head;
	wheel_timer_t *wt;
    glthread_t reschedule_glue;
    unsigned int N_scheduled;
    pthread_mutex_t mutex;
};
GLTHREAD_TO_STRUCT(glthread_to_wt_elem, wheel_timer_elem_t, glue);
GLTHREAD_TO_STRUCT(glthread_reschedule_glue_to_wt_elem, wheel_timer_elem_t, reschedule_glue);

static inline void
wt_elem_lock(wheel_timer_elem_t *wt_elem) {
	pthread_mutex_lock(&wt_elem->mutex);
}

static inline void
wt_elem_unlock(wheel_timer_elem_t *wt_elem) {
	pthread_mutex_unlock(&wt_elem->mutex);
}

static inline void *
wt_elem_get_and_set_app_data(wheel_timer_elem_t *wt_elem, void *new_data) {

	void *old_data = NULL;
	wt_elem_lock(wt_elem);
	old_data = wt_elem->arg;
	wt_elem->arg = new_data;
	wt_elem_unlock(wt_elem);
	return old_data;
}

struct _wheel_timer_t {
	int current_clock_tic;
	int clock_tic_interval;
	int wheel_size;
	int current_cycle_no;
	Timer_t *wheel_thread;
    slotlist_t reschd_list;
	timer_resolution_t timer_resolution;
	bool debug;
    slotlist_t slotlist[0];
};

#define WT_UPTIME(wt_ptr)  \
    ((GET_WT_CURRENT_ABS_SLOT_NO(wt_ptr) * wt_get_clock_interval_in_milli_sec(wt_ptr))/1000)

#define WT_SLOTLIST(wt_ptr, index)                              \
    (&(wt_ptr->slotlist[index]))

#define WT_SLOTLIST_HEAD(wt_ptr, index)                         \
    (&(wt_ptr->slotlist[index].slots))

#define WT_SLOTLIST_MUTEX(wt_ptr, index)                        \
    (&(wt_ptr->slotlist[index].slot_mutex))

#define GET_WT_ELEM_SLOT_LIST(wt_elem_ptr)                      \
    (wt_elem_ptr->slotlist_head)

#define WT_LOCK_SLOT_LIST(slotlist_ptr)                         \
     pthread_mutex_lock(&(slotlist_ptr->slot_mutex))

#define WT_UNLOCK_SLOT_LIST(slotlist_ptr)                       \
     pthread_mutex_unlock(&(slotlist_ptr->slot_mutex))

#define WT_LOCK_WTELEM_SLOT_LIST(wt_elem_ptr)                   \
{                                                               \
    slotlist_t *_slotlist = GET_WT_ELEM_SLOT_LIST(wt_elem_ptr); \
    if(_slotlist)                                               \
    WT_LOCK_SLOT_LIST(_slotlist);                               \
}

#define WT_UNLOCK_WTELEM_SLOT_LIST(wt_elem_ptr)                 \
{                                                               \
    slotlist_t *_slotlist = GET_WT_ELEM_SLOT_LIST(wt_elem_ptr); \
    if(_slotlist)                                               \
    WT_UNLOCK_SLOT_LIST(_slotlist);                             \
}

#define WT_IS_SLOTLIST_EMPTY(slotlist_ptr)  \
    IS_GLTHREAD_LIST_EMPTY(&(slotlist_ptr->slots))

#define WT_GET_RESCHD_SLOTLIST(wt_ptr)  \
    (&(wt_ptr->reschd_list))

#define WT_GET_RESCHD_SLOTLIST_HEAD(wt_ptr) \
    (&((WT_GET_RESCHD_SLOTLIST(wt_ptr))->slots))

wheel_timer_t*
init_wheel_timer(int wheel_size, int clock_tic_interval,
				 timer_resolution_t timer_resolution);


int
wt_get_remaining_time(wheel_timer_elem_t *wt_elem);

/*Gives the absolute slot no since the time WT has started*/
#define GET_WT_CURRENT_ABS_SLOT_NO(wt)	((wt->current_cycle_no * wt->wheel_size) + wt->current_clock_tic)

wheel_timer_elem_t * 
timer_register_app_event(wheel_timer_t *wt, 
		   app_call_back call_back, 
		   void *arg,
		   int arg_size, 
		   int time_interval, 
		   char is_recursive);

void
timer_de_register_app_event(wheel_timer_elem_t *wt_elem);

void
timer_reschedule(wheel_timer_elem_t *wt_elem, 
                   int new_time_interval);

void
free_wheel_timer_element(wheel_timer_elem_t *wt_elem);

void
print_wheel_timer(wheel_timer_t *wt);

void
start_wheel_timer(wheel_timer_t *wt);

void
cancel_wheel_timer(wheel_timer_t *wt);

void
reset_wheel_timer(wheel_timer_t *wt);

char*
hrs_min_sec_format(unsigned int seconds);

void
wt_enable_logging(wheel_timer_t *wt);

#endif
