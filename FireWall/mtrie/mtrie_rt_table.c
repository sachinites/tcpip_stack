#include <stdint.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <memory.h>
#include <stdio.h>
#include "mtrie.h"

// 1.2.3.4 --> INT
static uint32_t
covert_ip_p_to_n(char *ip_addr){

    uint32_t binary_prefix = 0;
    inet_pton(AF_INET, ip_addr, &binary_prefix);
    return htonl(binary_prefix);
}

// INT --> A.B.C.D
static char *
covert_ip_n_to_p(uint32_t ip_addr, 
                    char *output_buffer){

    char *out = NULL;
    static char str_ip[16];
    out = !output_buffer ? str_ip : output_buffer;
    memset(out, 0, 16);
    ip_addr = htonl(ip_addr);
    inet_ntop(AF_INET, &ip_addr, out, 16);
    out[15] = '\0';
    return out;
}

//24 --> 11111111 11111111 11111111 00000000
static uint32_t
convert_dmask_to_bin_mask(uint8_t dmask) {

    uint32_t bin_mask = 0xFFFFFFFF;
    bin_mask = bin_mask >> (32 - dmask);
    bin_mask = bin_mask << (32 - dmask);
    return bin_mask;
}

// 11111111 11111111 11111111 00000000 --> 24
static uint8_t
convert_bin_mask_to_dmask(uint32_t bin_mask) {

    uint8_t dmask = 0;

    while(bin_mask) {
        if (bin_mask & (1 << 31)) dmask++;
        bin_mask = bin_mask << 1;
    }
    return dmask;
}

int
main(int argc, char **argv) {

    mtrie_t mtrie = {NULL, 0};
    
    init_mtrie(&mtrie);

    char ip1[16] = "1.2.3.4";
    uint8_t dmask = 24;

    uint32_t bin_ip = covert_ip_p_to_n(ip1);
    uint32_t bin_mask = convert_dmask_to_bin_mask(dmask);

/*
    printf ("Test : %s/%d\n", 
            covert_ip_n_to_p(bin_ip, 0), 
            convert_bin_mask_to_dmask(bin_mask));
*/
#if 0
    mtrie_insert_prefix(&mtrie, bin_ip, ~bin_mask, 32, (void *)~0);

    strcpy(ip1, "1.2.0.0");
    bin_ip = covert_ip_p_to_n(ip1);
    bin_mask = convert_dmask_to_bin_mask(16);
    mtrie_insert_prefix(&mtrie, bin_ip, ~bin_mask, 32, (void *)~0);

    strcpy(ip1, "5.6.7.0");
    bin_ip = covert_ip_p_to_n(ip1);
    bin_mask = convert_dmask_to_bin_mask(8);
    mtrie_insert_prefix(&mtrie, bin_ip, ~bin_mask, 32, (void *)~0);

    strcpy(ip1, "100.1.2.3");
    bin_ip = covert_ip_p_to_n(ip1);
    bin_mask = convert_dmask_to_bin_mask(32);
    mtrie_insert_prefix(&mtrie, bin_ip, ~bin_mask, 32, (void *)~0);
#endif
    strcpy(ip1, "122.1.2.3\0");
    bin_ip = covert_ip_p_to_n(ip1);
    bin_mask = convert_dmask_to_bin_mask(32);
    mtrie_insert_prefix(&mtrie, bin_ip, ~bin_mask, 32, (void *)~0);

    strcpy(ip1, "0.0.0.1\0");
    bin_ip = covert_ip_p_to_n(ip1);
    bin_mask = convert_dmask_to_bin_mask(32);
    mtrie_insert_prefix(&mtrie, bin_ip, ~bin_mask, 32, (void *)~0);

    mtrie_print_ipv4(&mtrie);
    return 0;
}