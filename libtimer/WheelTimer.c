#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include "WheelTimer.h"
#include "../EventDispatcher/event_dispatcher.h"

int
insert_wt_elem_in_slot(void *data1, void *data2){

   wheel_timer_elem_t *wt_elem1 = (wheel_timer_elem_t *)data1;
   wheel_timer_elem_t *wt_elem2 = (wheel_timer_elem_t *)data2;

   if(wt_elem1->execute_cycle_no < wt_elem2->execute_cycle_no)
       return -1;

   if(wt_elem1->execute_cycle_no > wt_elem2->execute_cycle_no)
       return 1;

   return 0;
}

void
wt_enable_logging(wheel_timer_t *wt) {

	if(wt->debug)
		wt->debug = false;
	else
		wt->debug = true;
}

static uint32_t 
wt_get_clock_interval_in_milli_sec(
	wheel_timer_t *wt) {


	uint32_t clock_tick_interval_in_milli_sec;

	clock_tick_interval_in_milli_sec = 
		wt->timer_resolution == TIMER_MILLI_SECONDS ? 
		wt->clock_tic_interval :
		wt->clock_tic_interval * 1000;

	return clock_tick_interval_in_milli_sec;
}


static void
process_wt_reschedule_slotlist(wheel_timer_t *wt){

    glthread_t *curr;
    wheel_timer_elem_t *wt_elem;

    WT_LOCK_SLOT_LIST(WT_GET_RESCHD_SLOTLIST(wt));
	if(wt->debug){ printf("Reschedule slot list locked\n"); }
    if(WT_IS_SLOTLIST_EMPTY(WT_GET_RESCHD_SLOTLIST(wt))){
        WT_UNLOCK_SLOT_LIST(WT_GET_RESCHD_SLOTLIST(wt));
		if(wt->debug){ printf("Empty : Reschedule slot list unlocked\n"); }
        return;
    }

    ITERATE_GLTHREAD_BEGIN(WT_GET_RESCHD_SLOTLIST_HEAD(wt), curr){

        wt_elem = glthread_reschedule_glue_to_wt_elem(curr);
        remove_glthread(&wt_elem->glue);
        wt_elem->slotlist_head = NULL;
		if(wt->debug){ printf("Dequeue wt_elem %p from resched list with op_code = %d\n", wt_elem, wt_elem->opcode); }
        switch(wt_elem->opcode){
            case WTELEM_CREATE:
            case WTELEM_RESCHED:
            {
                assert(wt_elem->app_callback);
                wt_elem->time_interval = wt_elem->new_time_interval;
				assert(wt_elem->time_interval);
                int absolute_slot_no = GET_WT_CURRENT_ABS_SLOT_NO(wt);
                int next_abs_slot_no  = absolute_slot_no +
                    (wt_elem->time_interval/wt_get_clock_interval_in_milli_sec(wt));
                int next_cycle_no     = next_abs_slot_no / wt->wheel_size;
                int next_slot_no      = next_abs_slot_no % wt->wheel_size;
                wt_elem->execute_cycle_no    = next_cycle_no;
                wt_elem->slot_no = next_slot_no;
				if(wt->debug) {
					printf("inserting wt_elem %p into new position at [%u, %u]\n", 
					wt_elem, wt_elem->execute_cycle_no, next_slot_no);
				}
                glthread_priority_insert(WT_SLOTLIST_HEAD(wt, wt_elem->slot_no), 
                        &wt_elem->glue,
                        insert_wt_elem_in_slot, 
                        (unsigned long)&(((wheel_timer_elem_t *)0)->glue));
                wt_elem->slotlist_head = WT_SLOTLIST(wt, wt_elem->slot_no);
                remove_glthread(&wt_elem->reschedule_glue);
                wt_elem->N_scheduled++;
                wt_elem->opcode = WTELEM_SCHEDULED;
            }
            break;
            case WTELEM_DELETE:
                remove_glthread(&wt_elem->reschedule_glue);
				if(wt->debug){ printf("Freeing wt_elem %p\n", wt_elem); }
                free_wheel_timer_element(wt_elem);
                break;
			case WTELEM_SCHEDULED:
				break;
            default:
                assert(0);
        }
    }ITERATE_GLTHREAD_END(WT_GET_RESCHD_SLOTLIST_HEAD(wt), curr)
	if(wt->debug){ printf("resched list processed, unlocked\n"); }
    WT_UNLOCK_SLOT_LIST(WT_GET_RESCHD_SLOTLIST(wt));
}

static void
wheel_fn(Timer_t *timer, void *arg){

	wheel_timer_t *wt = (wheel_timer_t *)arg;
	wheel_timer_elem_t *wt_elem = NULL;
	int absolute_slot_no = 0, i =0;
	slotlist_t *slot_list = NULL;
	glthread_t *curr;

	wt->current_clock_tic++;
	if(wt->debug){ printf("\nwt->current_clock_tic = %u\n", wt->current_clock_tic); }

	if(wt->current_clock_tic == wt->wheel_size){
		wt->current_clock_tic = 0;
		wt->current_cycle_no++;
		if(wt->debug){ printf("Cycle no incremented to %u\n", wt->current_cycle_no); }
	}

	slot_list = WT_SLOTLIST(wt, wt->current_clock_tic);
	absolute_slot_no = GET_WT_CURRENT_ABS_SLOT_NO(wt);

	ITERATE_GLTHREAD_BEGIN(&slot_list->slots, curr){

		wt_elem = glthread_to_wt_elem(curr);

		/*Check if R == r*/
		if(wt->current_cycle_no == wt_elem->execute_cycle_no){
			/*Invoke the application event through fn pointer as below*/
			  
			  if(wt->debug){ printf("Creating new Task for wt_elem %p\n", wt_elem); }
			  pthread_mutex_lock(&wt_elem->mutex);
			  task_create_new_job(wt_elem->arg,
								  wt_elem->app_callback,
								  TASK_ONE_SHOT);
			  if (!wt_elem->is_recurrence) {
				remove_glthread(&wt_elem->glue); // appln must free it
			  }
			  pthread_mutex_unlock(&wt_elem->mutex);
			  if(wt->debug){ printf("Task for wt_elem %p is submitted\n", wt_elem); }

			/* After invocation, check if the event needs to be rescheduled again
			 * in future*/
			if(wt_elem->is_recurrence){

				if(wt->debug){ printf("Rescheduling wt_elem %p\n", wt_elem); }
				/*relocate Or reschedule to the next slot*/
				if(wt->debug){ printf("Current abs slot no = %u\n", absolute_slot_no); }
				int next_abs_slot_no  = absolute_slot_no + 
					(wt_elem->time_interval/wt_get_clock_interval_in_milli_sec(wt));
				if(wt->debug){ printf("Next abs slot no = %u\n", next_abs_slot_no); }
				int next_cycle_no     = next_abs_slot_no / wt->wheel_size;
				int next_slot_no      = next_abs_slot_no % wt->wheel_size;
				wt_elem->execute_cycle_no 	 = next_cycle_no;
				remove_glthread(&wt_elem->glue);
				glthread_priority_insert(WT_SLOTLIST_HEAD(wt, next_slot_no), &wt_elem->glue, 
						insert_wt_elem_in_slot, 
						(unsigned long)&(((wheel_timer_elem_t *)0)->glue));
				wt_elem->slotlist_head = WT_SLOTLIST(wt, next_slot_no);
				wt_elem->slot_no = next_slot_no;
				wt_elem->N_scheduled++;
				if(wt->debug){ printf("wt_elem %p is rescheduled in [%u, %u]\n", wt_elem,  wt_elem->execute_cycle_no, next_slot_no); }
			}
			else {
				remove_glthread(&wt_elem->glue);
			}
		}
		else {
			if(wt->debug){ printf("wt_elem %p will be cleaned up\n", wt_elem); }
			break;
		}
	} ITERATE_GLTHREAD_END(slot_list, curr)
	process_wt_reschedule_slotlist(wt);
}

wheel_timer_t*
init_wheel_timer(int wheel_size, int clock_tic_interval,
				 timer_resolution_t timer_resolution){
	
	wheel_timer_t *wt = calloc(1, sizeof(wheel_timer_t) + 
				(wheel_size * sizeof(slotlist_t)));

	wt->clock_tic_interval = clock_tic_interval;
	wt->wheel_size = wheel_size;

	wt->wheel_thread = setup_timer(wheel_fn,
							timer_resolution == TIMER_MILLI_SECONDS ? \
								wt->clock_tic_interval : wt->clock_tic_interval * 1000,
							timer_resolution == TIMER_MILLI_SECONDS ? \
								wt->clock_tic_interval : wt->clock_tic_interval * 1000,
							0,
							(void *)wt,
							false);

	wt->timer_resolution = timer_resolution;

	int i = 0;

	for(; i < wheel_size; i++){
        init_glthread(WT_SLOTLIST_HEAD(wt, i));
        pthread_mutex_init(WT_SLOTLIST_MUTEX(wt, i), NULL);
    }
	return wt;
}


static void
_timer_reschedule(wheel_timer_t *wt, 
                    wheel_timer_elem_t *wt_elem, 
                    int new_time_interval, 
                    wt_opcode_t opcode){

	if (wt->debug) { printf("%s() called wt_elem %p , opcode = %d\n", __FUNCTION__, wt_elem, opcode); }
    switch(opcode){
        case WTELEM_CREATE:
        case WTELEM_RESCHED:
        case WTELEM_DELETE:
               wt_elem->opcode = opcode;
               wt_elem->new_time_interval = new_time_interval;
			
               WT_LOCK_SLOT_LIST(WT_GET_RESCHD_SLOTLIST(wt));
			   wt_elem->slotlist_head = NULL;
               remove_glthread(&wt_elem->reschedule_glue);
               glthread_add_next(WT_GET_RESCHD_SLOTLIST_HEAD(wt), 
               		&wt_elem->reschedule_glue);
			   if (wt->debug) { printf("%s() wt_elem %p Added to Reschedule Q\n", __FUNCTION__, wt_elem); }
               WT_UNLOCK_SLOT_LIST(WT_GET_RESCHD_SLOTLIST(wt));
 			
            break;
        default:
            assert(0);
    }
}


wheel_timer_elem_t *
timer_register_app_event(wheel_timer_t *wt,
		app_call_back call_back,
		void *arg,
		int arg_size,
		int time_interval,	/* in milli sec */
		char is_recursive){

	if(!wt || !call_back) return NULL;
	
	uint32_t clock_tick_interval_in_milli_sec = 
					wt_get_clock_interval_in_milli_sec(wt);

	if((!time_interval || 
	   (time_interval % clock_tick_interval_in_milli_sec) != 0)){		
		
		assert(0);
	}

	wheel_timer_elem_t *wt_elem = calloc(1, sizeof(wheel_timer_elem_t));
	wt_elem->wt = wt;
	wt_elem->app_callback  = call_back;
    if(arg && arg_size){
        wt_elem->arg 	       = arg;
        wt_elem->arg_size      = arg_size;
    }
	wt_elem->is_recurrence = is_recursive;
    init_glthread(&wt_elem->glue);
    init_glthread(&wt_elem->reschedule_glue);
    wt_elem->N_scheduled = 0;
    pthread_mutex_init(&wt_elem->mutex, NULL);
    _timer_reschedule(wt, wt_elem, time_interval, WTELEM_CREATE);
    return wt_elem;
}

void
timer_de_register_app_event(wheel_timer_elem_t *wt_elem){

    wt_elem_get_and_set_app_data(wt_elem, 0);
    _timer_reschedule(wt_elem->wt, wt_elem, 0, WTELEM_DELETE);
}

void
timer_reschedule(wheel_timer_elem_t *wt_elem, 
                   int new_time_interval){
  
	wheel_timer_t *wt = wt_elem->wt;
	
	if (!new_time_interval ||
		(new_time_interval % wt_get_clock_interval_in_milli_sec(wt) != 0)){

		assert(0);
	}   

    _timer_reschedule(wt, wt_elem, new_time_interval, WTELEM_RESCHED);    
}

int
wt_get_remaining_time(wheel_timer_elem_t *wt_elem){

	wheel_timer_t *wt = wt_elem->wt;
    if(wt_elem->opcode == WTELEM_CREATE || 
        wt_elem->opcode == WTELEM_RESCHED){
        /* Means : the wt_elem has not been assigned a slot in WT,
         * just return the time interval for which it has been scheduled
         * in this case*/
        return wt_elem->new_time_interval;
    }
    int wt_elem_absolute_slot = (wt_elem->execute_cycle_no * wt->wheel_size) + 
            wt_elem->slot_no;
    int diff = wt_elem_absolute_slot - GET_WT_CURRENT_ABS_SLOT_NO(wt);
    return (diff * wt_get_clock_interval_in_milli_sec(wt));
}

void
free_wheel_timer_element(wheel_timer_elem_t *wt_elem){
    
    wt_elem->slotlist_head = NULL;
	free(wt_elem);
}


void
print_wheel_timer(wheel_timer_t *wt){
	
    int i = 0, j = 0;
	glthread_t *curr;
    glthread_t *slot_list_head = NULL;
	wheel_timer_elem_t *wt_elem = NULL;

	printf("Printing Wheel Timer DS\n");
	printf("wt->current_clock_tic  = %d\n", wt->current_clock_tic);
	printf("wt->clock_tic_interval = %d\n", wt->clock_tic_interval);
    printf("wt abs slot no         = %d\n", GET_WT_CURRENT_ABS_SLOT_NO(wt));
	printf("wt->wheel_size         = %d\n", wt->wheel_size);
	printf("wt->current_cycle_no   = %d\n", wt->current_cycle_no);
	printf("wt->wheel_thread       = %p\n", &wt->wheel_thread);
    printf("WT uptime              = %s\n", hrs_min_sec_format(WT_UPTIME(wt)));
	printf("wt->timer_thread state = %u\n", timer_get_current_state(wt->wheel_thread));
	printf("printing slots : \n");

	for(; i < wt->wheel_size; i++){
        slot_list_head = WT_SLOTLIST_HEAD(wt, i);
        ITERATE_GLTHREAD_BEGIN(slot_list_head, curr){
            wt_elem = glthread_to_wt_elem(curr);
            printf("                wt_elem->opcode             = %d\n", wt_elem->opcode);
            printf("                wt_elem                     = %p\n",  wt_elem);
			printf("                wt_elem->time_interval		= %d\n",  wt_elem->time_interval);
			printf("                wt_elem->execute_cycle_no	= %d\n",  wt_elem->execute_cycle_no);
            printf("                wt_elem->slot_no            = %d\n",  wt_elem->slot_no);
            printf("                wt_elem abs slot no         = %d\n",  
                                    (wt_elem->execute_cycle_no * wt->wheel_size) + wt_elem->slot_no);
			printf("                wt_elem->app_callback		= %p\n",  wt_elem->app_callback);
			printf("                wt_elem->arg    			= %p\n",  wt_elem->arg);
			printf("                wt_elem->is_recurrence		= %d\n",  wt_elem->is_recurrence);
            printf("                wt_elem->N_scheduled        = %u\n",  wt_elem->N_scheduled);
            printf("                Remaining Time to Fire      = %d\n",  
                                    wt_get_remaining_time(wt_elem));
            printf("\n");
        } ITERATE_GLTHREAD_END(slot_list_head , curr)
	}
}

void
start_wheel_timer(wheel_timer_t *wt){

	start_timer(wt->wheel_thread);
}

void
reset_wheel_timer(wheel_timer_t *wt){
	wt->current_clock_tic = 0;
	wt->current_cycle_no  = 0;
}


char*
hrs_min_sec_format(unsigned int seconds){

    static char time_f[16];
    unsigned int hrs = 0,
                 min =0, sec = 0;

    if(seconds > 3600){
        min = seconds/60;
        sec = seconds%60;
        hrs = min/60;
        min = min%60;
    }
    else{
        min = seconds/60;
        sec = seconds%60;
    }
    memset(time_f, 0, sizeof(time_f));
    sprintf(time_f, "%u::%u::%u", hrs, min, sec);
    return time_f;
}

void
cancel_wheel_timer(wheel_timer_t *wt){

	if(wt->wheel_thread){
		cancel_timer(wt->wheel_thread);
	}
}

