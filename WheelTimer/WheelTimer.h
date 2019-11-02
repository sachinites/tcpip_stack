#ifndef __WHEEL_TIMER__
#define __WHEEL_TIMER__

#include <pthread.h>
#include "gluethread/glthread.h"

typedef struct _wheel_timer_elem_t wheel_timer_elem_t;
typedef void (*app_call_back)(void *arg, int sizeof_arg);

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
    glthread_t reschedule_glue;
    unsigned int N_scheduled;
};
GLTHREAD_TO_STRUCT(glthread_to_wt_elem, wheel_timer_elem_t, glue);
GLTHREAD_TO_STRUCT(glthread_reschedule_glue_to_wt_elem, wheel_timer_elem_t, reschedule_glue);

typedef struct _wheel_timer_t {
	int current_clock_tic;
	int clock_tic_interval;
	int wheel_size;
	int current_cycle_no;
	pthread_t wheel_thread;
    slotlist_t reschd_list;
    unsigned int no_of_wt_elem;
    slotlist_t slotlist[0];
} wheel_timer_t;

#define WT_UPTIME(wt_ptr)  \
    (GET_WT_CURRENT_ABS_SLOT_NO(wt_ptr) * wt_ptr->clock_tic_interval)

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
init_wheel_timer(int wheel_size, int clock_tic_interval);


int
wt_get_remaining_time(wheel_timer_t *wt,
                   wheel_timer_elem_t *wt_elem);

/*Gives the absolute slot no since the time WT has started*/
#define GET_WT_CURRENT_ABS_SLOT_NO(wt)	((wt->current_cycle_no * wt->wheel_size) + wt->current_clock_tic)

wheel_timer_elem_t * 
register_app_event(wheel_timer_t *wt, 
		   app_call_back call_back, 
		   void *arg,
		   int arg_size, 
		   int time_interval, 
		   char is_recursive);

void
de_register_app_event(wheel_timer_t *wt, wheel_timer_elem_t *wt_elem);

void
wt_elem_reschedule(wheel_timer_t *wt, 
                   wheel_timer_elem_t *wt_elem, 
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

#endif
