#include "WheelTimer.h"
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <unistd.h>
#include <time.h>

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

/* Note : This wheel timer implementation do not maintain the list of events in
 * a slot in sorted manner based on r value of events. This is 
 * design defect. But as discussed in the tutorial, you need to
 * maintain the list of event sorted based on r value*/

wheel_timer_t*
init_wheel_timer(int wheel_size, int clock_tic_interval){
	wheel_timer_t *wt = calloc(1, sizeof(wheel_timer_t) + 
				wheel_size*sizeof(glthread_t));

	wt->clock_tic_interval = clock_tic_interval;
	wt->wheel_size = wheel_size;

    memset(&(wt->wheel_thread), 0, sizeof(wheel_timer_t));

	int i = 0;
	for(; i < wheel_size; i++)
        init_glthread(&wt->slots[i]);

	return wt;
}

void
de_register_app_event(wheel_timer_elem_t *wt_elem){

    /* Remove the Wheel timer element from Wheel timer. How will you search
     * in which slot it is ? It shall be inefficient to search in all slots of
     * wheel timer.*/

    remove_glthread(&wt_elem->glue);
    free_wheel_timer_element(wt_elem);
}


static void*
wheel_fn(void *arg){

	wheel_timer_t *wt = (wheel_timer_t *)arg;
	wheel_timer_elem_t *wt_elem = NULL;
	int absolute_slot_no = 0, i =0;
	glthread_t *slot_list = NULL;
	glthread_t *curr;

	while(1){
        
        wt->current_clock_tic++;
        if(wt->current_clock_tic == wt->wheel_size)
            wt->current_clock_tic = 0;

		if(wt->current_clock_tic == 0)
			wt->current_cycle_no++;

		sleep(wt->clock_tic_interval);

		slot_list = &wt->slots[wt->current_clock_tic];
		absolute_slot_no = GET_WT_CURRENT_ABS_SLOT_NO(wt);
		//printf("Wheel Timer Time = %d : ", absolute_slot_no * wt->clock_tic_interval);
		if(IS_GLTHREAD_LIST_EMPTY(slot_list))
			printf("\n");

         /* This is a macro to iterate over a linked list. While 
          * iterating over a linked list, even if you delete the current node
          * being processes "head" , the loop still runs fine. You should
          * learn show to write such looping macros in C*/
		 ITERATE_GLTHREAD_BEGIN(slot_list, curr){

            wt_elem = glthread_to_wt_elem(curr);

            /*Check if R == r*/
			if(wt->current_cycle_no == wt_elem->execute_cycle_no){
                /*Invoke the application event through fn pointer as below*/
				wt_elem->app_callback(wt_elem->arg, wt_elem->arg_size);

                /*After invocation, check if the event needs to be rescheduled again
                 * in future*/
				if(wt_elem->is_recurrence){
					
                    /*relocate Or reschedule to the next slot*/
					int next_abs_slot_no  = absolute_slot_no + 
                            (wt_elem->time_interval/wt->clock_tic_interval);
					int next_cycle_no     = next_abs_slot_no / wt->wheel_size;
					int next_slot_no      = next_abs_slot_no % wt->wheel_size;
					wt_elem->execute_cycle_no 	 = next_cycle_no;

                    /*It might be possible that next slot no could be same as 
                     * where the current clock time is. Inb this case, simply
                     * update the r value and adjust the wt_elem position
                     * in the linked list in the increasing order of r value*/
					if(next_slot_no == wt->current_clock_tic){
						continue;
					}
                    /*Remove from Event from the old slot*/
                    remove_glthread(curr);
                    /*Add the event to the new slot*/
					glthread_priority_insert(&wt->slots[next_slot_no], &wt_elem->glue, 
                                    insert_wt_elem_in_slot, 
                                    (unsigned int)&((wheel_timer_elem_t *)0)->glue);
				}
				else{
                    remove_glthread(curr);
					free_wheel_timer_element(wt_elem);
				}
			}
        } ITERATE_GLTHREAD_END(slot_list, curr)
	}
	return NULL;
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

	wt_elem->time_interval = time_interval;
	wt_elem->app_callback  = call_back;
	wt_elem->arg 	       = calloc(1, arg_size);
	memcpy(wt_elem->arg, arg, arg_size);
	wt_elem->arg_size      = arg_size;
	wt_elem->is_recurrence = is_recursive;
    init_glthread(&wt_elem->glue);
	int wt_absolute_slot = GET_WT_CURRENT_ABS_SLOT_NO(wt);
	int registration_next_abs_slot = wt_absolute_slot + (wt_elem->time_interval/wt->clock_tic_interval);
	int cycle_no = registration_next_abs_slot / wt->wheel_size;
	int slot_no  = registration_next_abs_slot % wt->wheel_size;
	wt_elem->execute_cycle_no = cycle_no;
    glthread_priority_insert(&wt->slots[slot_no], &wt_elem->glue, 
            insert_wt_elem_in_slot, 
            (unsigned int)&((wheel_timer_elem_t *)0)->glue);
	return wt_elem;
}

void
free_wheel_timer_element(wheel_timer_elem_t *wt_elem){
	free(wt_elem->arg);
	free(wt_elem);
}


void
print_wheel_timer(wheel_timer_t *wt){
	
    int i = 0, j = 0;
	glthread_t* slot_list = NULL;
	wheel_timer_elem_t *wt_elem = NULL;
	glthread_t *curr;

	printf("Printing Wheel Timer DS\n");
	printf("wt->current_clock_tic  = %d\n", wt->current_clock_tic);
	printf("wt->clock_tic_interval = %d\n", wt->clock_tic_interval);
	printf("wt->wheel_size         = %d\n", wt->wheel_size);
	printf("wt->current_cycle_no   = %d\n", wt->current_cycle_no);
	printf("wt->wheel_thread       = %p\n", &wt->wheel_thread);
	printf("printing slots : \n");

	for(; i < wt->wheel_size; i++){
		slot_list = &wt->slots[i];
        ITERATE_GLTHREAD_BEGIN(slot_list , curr){
            wt_elem = glthread_to_wt_elem(curr); 
			printf("		        wt_elem->time_interval		= %d\n",  wt_elem->time_interval);
			printf("                wt_elem->execute_cycle_no	= %d\n",  wt_elem->execute_cycle_no);
			printf("                wt_elem->app_callback		= %p\n",  wt_elem->app_callback);
			printf("                wt_elem->arg			= %p\n",  wt_elem->arg);
			printf("                wt_elem->is_recurrence		= %d\n",  wt_elem->is_recurrence);
        } ITERATE_GLTHREAD_END(slot_list , curr)
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

