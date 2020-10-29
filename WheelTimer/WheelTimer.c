#include "WheelTimer.h"
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>

#define TH_JOINABLE	1
#define TH_DETACHED	0


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

wheel_timer_t*
init_wheel_timer(int wheel_size, int clock_tic_interval){
	wheel_timer_t *wt = calloc(1, sizeof(wheel_timer_t) + 
				(wheel_size * sizeof(slotlist_t)));

	wt->clock_tic_interval = clock_tic_interval;
	wt->wheel_size = wheel_size;

    memset(&(wt->wheel_thread), 0, sizeof(wheel_timer_t));

	int i = 0;
	for(; i < wheel_size; i++){
        init_glthread(WT_SLOTLIST_HEAD(wt, i));
        pthread_mutex_init(WT_SLOTLIST_MUTEX(wt, i), NULL);
    }
    wt->no_of_wt_elem = 0;
	return wt;
}

static void
process_wt_reschedule_slotlist(wheel_timer_t *wt){

    glthread_t *curr;
    wheel_timer_elem_t *wt_elem;

    WT_LOCK_SLOT_LIST(WT_GET_RESCHD_SLOTLIST(wt));
    if(WT_IS_SLOTLIST_EMPTY(WT_GET_RESCHD_SLOTLIST(wt))){
        WT_UNLOCK_SLOT_LIST(WT_GET_RESCHD_SLOTLIST(wt));
        return;
    }

    ITERATE_GLTHREAD_BEGIN(WT_GET_RESCHD_SLOTLIST_HEAD(wt), curr){

        wt_elem = glthread_reschedule_glue_to_wt_elem(curr);
        remove_glthread(&wt_elem->glue);
        wt_elem->slotlist_head = NULL;

        switch(wt_elem->opcode){
            case WTELEM_CREATE:
            case WTELEM_RESCHED:
            {
                assert(wt_elem->app_callback);
                wt_elem->time_interval = wt_elem->new_time_interval;
                int absolute_slot_no = GET_WT_CURRENT_ABS_SLOT_NO(wt);
                int next_abs_slot_no  = absolute_slot_no +
                    (wt_elem->time_interval/wt->clock_tic_interval);
                int next_cycle_no     = next_abs_slot_no / wt->wheel_size;
                int next_slot_no      = next_abs_slot_no % wt->wheel_size;
                wt_elem->execute_cycle_no    = next_cycle_no;
                wt_elem->slot_no = next_slot_no;
                glthread_priority_insert(WT_SLOTLIST_HEAD(wt, wt_elem->slot_no), 
                        &wt_elem->glue,
                        insert_wt_elem_in_slot, 
                        (unsigned long)&((wheel_timer_elem_t *)0)->glue);
                wt_elem->slotlist_head = WT_SLOTLIST(wt, wt_elem->slot_no);
                remove_glthread(&wt_elem->reschedule_glue);
                wt_elem->N_scheduled++;
                if(wt_elem->opcode == WTELEM_CREATE){
                    wt->no_of_wt_elem++;
                }
                wt_elem->opcode = WTELEM_SCHEDULED;
            }
                break;
            case WTELEM_DELETE:
                remove_glthread(&wt_elem->reschedule_glue);
                free_wheel_timer_element(wt_elem);
                wt->no_of_wt_elem--;
                break;
            default:
                assert(0);
        }
    }ITERATE_GLTHREAD_END(WT_GET_RESCHD_SLOTLIST_HEAD(wt), curr)
    WT_UNLOCK_SLOT_LIST(WT_GET_RESCHD_SLOTLIST(wt));
}


static void *
wheel_fn(void *arg){

	wheel_timer_t *wt = (wheel_timer_t *)arg;
	wheel_timer_elem_t *wt_elem = NULL;
	int absolute_slot_no = 0, i =0;
    slotlist_t *slot_list = NULL;
	glthread_t *curr;

	while(1){
        
        wt->current_clock_tic++;
        if(wt->current_clock_tic == wt->wheel_size){
            wt->current_clock_tic = 0;
            wt->current_cycle_no++;
        }

		sleep(wt->clock_tic_interval);

		slot_list = WT_SLOTLIST(wt, wt->current_clock_tic);
		absolute_slot_no = GET_WT_CURRENT_ABS_SLOT_NO(wt);

		 ITERATE_GLTHREAD_BEGIN(&slot_list->slots, curr){

            wt_elem = glthread_to_wt_elem(curr);
           
            /*Check if R == r*/
			if(wt->current_cycle_no == wt_elem->execute_cycle_no){
                /*Invoke the application event through fn pointer as below*/
				wt_elem->app_callback(wt_elem->arg, wt_elem->arg_size);

                /* After invocation, check if the event needs to be rescheduled again
                 * in future*/
				if(wt_elem->is_recurrence){

                    /*relocate Or reschedule to the next slot*/
					int next_abs_slot_no  = absolute_slot_no + 
                            (wt_elem->time_interval/wt->clock_tic_interval);
					int next_cycle_no     = next_abs_slot_no / wt->wheel_size;
					int next_slot_no      = next_abs_slot_no % wt->wheel_size;
					wt_elem->execute_cycle_no 	 = next_cycle_no;
                    remove_glthread(&wt_elem->glue);
					glthread_priority_insert(WT_SLOTLIST_HEAD(wt, next_slot_no), &wt_elem->glue, 
                                    insert_wt_elem_in_slot, 
                                    (unsigned long)&((wheel_timer_elem_t *)0)->glue);
                    wt_elem->slotlist_head = WT_SLOTLIST(wt, next_slot_no);
                    wt_elem->slot_no = next_slot_no;
                    wt_elem->N_scheduled++;
				}
			}
            else
                break;
        } ITERATE_GLTHREAD_END(slot_list, curr)
        process_wt_reschedule_slotlist(wt);
	}
	return NULL;
}

static void
_wt_elem_reschedule(wheel_timer_t *wt, 
                    wheel_timer_elem_t *wt_elem, 
                    int new_time_interval, 
                    wt_opcode_t opcode){

    if(wt_elem->opcode == WTELEM_DELETE && 
        (opcode == WTELEM_CREATE || 
         opcode == WTELEM_RESCHED)){
        /* This is a Valid Scenario. A Race condition may arise When WT itself
         * invoked a timer expiry callback for a wt_elem, and at the same time 
         * hello packet also arrived to refresh the same wt_elem.*/
        //assert(0);
    } 
    switch(opcode){
        case WTELEM_CREATE:
        case WTELEM_RESCHED:
        case WTELEM_DELETE:
            
               wt_elem->new_time_interval = new_time_interval;
               WT_LOCK_SLOT_LIST(WT_GET_RESCHD_SLOTLIST(wt));
               wt_elem->opcode = opcode;
               remove_glthread(&wt_elem->reschedule_glue);
               glthread_add_next(WT_GET_RESCHD_SLOTLIST_HEAD(wt), 
                &wt_elem->reschedule_glue);
               WT_UNLOCK_SLOT_LIST(WT_GET_RESCHD_SLOTLIST(wt));         
            break;
        default:
            assert(0);
    }
}


wheel_timer_elem_t *
register_app_event(wheel_timer_t *wt,
		app_call_back call_back,
		void *arg,
		int arg_size,
		int time_interval,
		char is_recursive){

	if(!wt || !call_back) return NULL;
	wheel_timer_elem_t *wt_elem = calloc(1, sizeof(wheel_timer_elem_t));
	wt_elem->app_callback  = call_back;
    if(arg && arg_size){
		wt_elem->arg = arg;
        wt_elem->arg_size      = arg_size;
    }
	wt_elem->is_recurrence = is_recursive;
    init_glthread(&wt_elem->glue);
    init_glthread(&wt_elem->reschedule_glue);
    wt_elem->N_scheduled = 0;
	wt_elem->wt = wt;
    _wt_elem_reschedule(wt, wt_elem, time_interval, WTELEM_CREATE);
    return wt_elem;
}

void
de_register_app_event(wheel_timer_elem_t *wt_elem){

    _wt_elem_reschedule(wt_elem->wt, wt_elem, 0, WTELEM_DELETE);
}

void
wt_elem_reschedule(wheel_timer_elem_t *wt_elem, 
                   int new_time_interval){
   
    _wt_elem_reschedule(wt_elem->wt, wt_elem, new_time_interval, WTELEM_RESCHED);    
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
    return (diff * wt->clock_tic_interval);
}

void
free_wheel_timer_element(wheel_timer_elem_t *wt_elem){
    
    wt_elem->slotlist_head = NULL;
	wt_elem->wt = NULL;
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
    printf("wt->no_of_wt_elem      = %u\n", wt->no_of_wt_elem);
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

	if (pthread_create(&wt->wheel_thread, NULL, wheel_fn, (void*)wt))
	{
		printf("Wheel Timer Thread initialization failed, exiting ... \n");
		exit(0);
	}
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

