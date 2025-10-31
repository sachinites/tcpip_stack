#include "rtm_api.h"
#include "rtm_storage.h"


extern void rtm_initialize () ;

int
main (int argc, char **argv) {

    rtm_initialize ();
    rtm_t *rtm = rtm_init(1, RTM_AF_IPV4);
    return 0;
} 