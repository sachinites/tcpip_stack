#include "utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_MASK_LEN 32
void
apply_mask(char *prefix, char mask, char *str_prefix){

    struct in_addr addr;
    if(inet_aton(prefix, &addr) == 0)
        exit(EXIT_FAILURE);

    long fulmask = 0XFFFFFFFF;
    int mask_tail_bits = MAX_MASK_LEN - mask;
    
    addr.s_addr = htonl(inet_addr(prefix));
    addr.s_addr = addr.s_addr & (fulmask << mask_tail_bits);
    addr.s_addr = htonl(addr.s_addr);
    //puts(inet_ntoa(addr));
    //strncpy(str_prefix, inet_ntoa(addr), strlen(str_prefix));
    strcpy(str_prefix, inet_ntoa(addr));
    //printf("The subnet is %s\n", str_prefix);
}

void
layer2_fill_with_broadcast_mac(char *mac_array){

    mac_array[0] = 0xFF;
    mac_array[1] = 0xFF;
    mac_array[2] = 0xFF;
    mac_array[3] = 0xFF;
    mac_array[4] = 0xFF;
    mac_array[5] = 0xFF;
}