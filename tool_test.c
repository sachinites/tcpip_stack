#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define MAX_MASK_LEN 32

int main(int argc, char **argv){

    // char *ip_addr = argv[1];

    // printf("IP is %s\n", ip_addr);

    // int ip = inet_addr(ip_addr);

    // int mask = atoi(argv[2]);

    // struct in_addr addr;
    // if(inet_aton(ip_addr, &addr) == 0)
    //     exit(EXIT_FAILURE);

    // long fulmask = 0XFFFFFFFF;

    // int mask_tail_bits = MAX_MASK_LEN - mask;
    
    // addr.s_addr = htonl(inet_addr(ip_addr));
    // addr.s_addr = addr.s_addr & (fulmask << mask_tail_bits);
    // addr.s_addr = htonl(addr.s_addr);
    // //puts(inet_ntoa(addr));
    // //strncpy(str_prefix, inet_ntoa(addr), strlen(str_prefix));
    // char *str_prefix = inet_ntoa(addr);
    // printf("The subnet is %s\n", str_prefix);

    char mac[6];
    char mac_array[6];
    // mac[0] = 0xFF;
    // mac[1] = 0xFF;
    // mac[2] = 0xFF;
    // mac[3] = 0xFF;
    // mac[4] = 0xFF;
    // mac[5] = 0xFF;

    // printf("Mac is %s\n", mac);

    long fulmask = 0XFFFFFF;
    sprintf(mac_array, "%lx", fulmask);
    printf("Mac array is %s\n", mac_array);

    char *ptr_1 = mac_array;
    char *ptr_2 = mac_array + strlen(mac_array);

    printf("Addr of ptr_1 is %p and of ptr_2 is %p.", (void *)ptr_1, (void *)ptr_2);
    return 0;
}