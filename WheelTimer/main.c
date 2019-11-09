#include <stdio.h>
#include "WheelTimer.h"
#include <string.h>

#define WHEEL_SIZE 10
#define WHEEL_TIMER_CLOCK_TIC_INTERVAL 1

/* Application routine to be (indirectly) invoked by Wheel timer.
 * It could be of any prototype*/
void
print_hello(char *S){ 
    printf("%s\n", S);
}

/* But Only routines (Events) which have prototype : void *(fn)(void *arg, int arg_size) 
 * could be registered with wheel timer. Therefore, we need to encapsulate
 * the actual routine print_hello() to be invoked inside the routine of 
 * void *(fn)(void *arg, int arg_size) prototype. It is the wrapper which will be registered 
 * with wheel timer and invoked by wheel timer. We will unwrap the argument and invoke the actual 
 * appln routine with correct arguments. This technique is called 'Masking of routines'*/

void wrapper_print_hello(void *arg, int arg_size){
    char *S = (char *)arg;
    print_hello(S);
}

int
main(int argc, char **argv){

    /*create a wheel timer object*/
    wheel_timer_t *wt = init_wheel_timer(WHEEL_SIZE, WHEEL_TIMER_CLOCK_TIC_INTERVAL);
    /*start the wheel timer thread*/
    start_wheel_timer(wt);

    /*Now Wheel timer has started running in a separte thread. 
     * Register the events to be triggered with Wheel timer now.*/

    wheel_timer_elem_t * wt_elem = 
        register_app_event(wt, wrapper_print_hello, "MyString", 
                           strlen("MyString"), 
                           5,  /*wrapper_print_hello fn will be called after every 5 seconds*/
                           1); /*1 indefinitely, 0 only once : call for wrapper_print_hello*/

    wt_elem = 
        register_app_event(wt, wrapper_print_hello, "Udemy", 
                           strlen("Udemy"), 
                           3,  /*wrapper_print_hello fn will be called after every 5 seconds*/
                           1); /*1 indefinitely, 0 only once : call for wrapper_print_hello*/
    /*stop the main program from gettin terminated, otherwise wheel timer
     * thread we created will also get terminated*/
    scanf("\n");
    return 0;
}
