#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#define MAX_MASK_LEN 32

int main(int argc, char **argv){

    char *ip_addr = argv[1];

    printf("IP is %s\n", ip_addr);

    int ip = inet_addr(ip_addr);

    int mask = atoi(argv[2]);

    struct in_addr addr;
    if(inet_aton(ip_addr, &addr) == 0)
        exit(EXIT_FAILURE);

    long fulmask = 0XFFFFFFFF;
    int mask_tail_bits = MAX_MASK_LEN - mask;
    
    addr.s_addr = htonl(inet_addr(ip_addr));
    addr.s_addr = addr.s_addr & (fulmask << mask_tail_bits);
    addr.s_addr = htonl(addr.s_addr);
    //puts(inet_ntoa(addr));
    //strncpy(str_prefix, inet_ntoa(addr), strlen(str_prefix));
    char *str_prefix = inet_ntoa(addr);
    printf("The subnet is %s\n", str_prefix);
}