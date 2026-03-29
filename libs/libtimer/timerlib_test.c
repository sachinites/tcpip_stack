#include <stdio.h>
#include "timerlib.h"

static void
app_cb(Timer_t *timer, void *user_data){

	time_t t;
    time(&t);
    printf("%s ",ctime(&t));
	printf("%s() invoked ... name = %s, counter = %u, Threshold = %u,"
			" exp_time = %lu, sec_exp_time = %lu\n",
		 __FUNCTION__, (char *)user_data, timer->invocation_counter,
		timer->thresdhold, timespec_to_millisec(&timer->ts.it_value),
		timespec_to_millisec(&timer->ts.it_interval));
}

int
main(int argc, char **argv){

	char *name = "Abhishek";

	Timer_t *timer = setup_timer(app_cb, 50 , 50, 0, name, true);
	start_timer(timer);

	printf("1. Pause Timer\n");
	printf("2. Resume Timer\n");
	printf("3. Restart timer\n");
	printf("4. Reschedule timer\n");
	printf("5. Delete timer\n");
	printf("6. Cancel Timer\n");
	printf("7. Get Remaining Time\n");
	printf("8. Print Timer State\n");

	int choice;
	choice = 0;

	while(1){
	scanf("%d", &choice);

	switch(choice){

		case 1:
			pause_timer(timer);
			break;
		case 2:
			resume_timer(timer);
			break;
		case 3:
			restart_timer(timer);
			break;
		case 4:
			reschedule_timer(timer, 
				timer->exp_timer, 
				timer->sec_exp_timer);
			break;
		case 5:
			delete_timer(timer);
			break;
		case 6:
			cancel_timer(timer);
			break;
		case 7:
			printf("Rem Time = %lu\n", timer_get_time_remaining_in_mill_sec(timer));
			break;
		case 8:
			print_timer(timer);
			break;
		deafault:	;
	}
	}
	pause();
	return 0;
}
