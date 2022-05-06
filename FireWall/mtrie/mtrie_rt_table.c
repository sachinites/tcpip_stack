#include <stdint.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include "mtrie.h"

// 1.2.3.4 --> INT
static uint32_t
covert_ip_p_to_n(char *ip_addr){

    uint32_t binary_prefix = 0;
    inet_pton(AF_INET, ip_addr, &binary_prefix);
    binary_prefix =  htonl(binary_prefix);
    return binary_prefix;
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
    if (dmask == 0) return 0;
    /* dont use below code for dmask = 0, undefined behavior */
    bin_mask = (bin_mask >> (32 - dmask));
    bin_mask = (bin_mask << (32 - dmask));
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

typedef struct prefix_ {

    uint32_t prefix;
    uint32_t mask;
}  prefix_t ;

static prefix_t *
create_prefix(uint32_t prefix, uint32_t mask) {

    prefix_t *_prefix = (prefix_t *)calloc(1, sizeof(prefix_t));
    _prefix->prefix = prefix;
    _prefix->mask = mask;
    return _prefix;
}

static void
ipv4_route_print (uint32_t prefix, uint32_t mask) {

    bit_type_t bit;
    char cidr_ip[16];
    uint8_t dmask = 0, index;

    dmask = convert_bin_mask_to_dmask(mask);

    prefix = htonl(prefix);

    inet_ntop(AF_INET, &prefix, cidr_ip, 16);

    cidr_ip[15] = '\0';

    printf ("Route = %s/%d\n", cidr_ip, dmask);
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

   // mtrie_insert_prefix(&mtrie, bin_ip, ~bin_mask, 32, 
     //                   (void *)create_prefix(bin_ip, bin_mask));


    strcpy(ip1, "0.0.0.0");
    bin_ip = covert_ip_p_to_n(ip1);
    bin_mask = convert_dmask_to_bin_mask(0);
    mtrie_insert_prefix(&mtrie, bin_ip, ~bin_mask, 32, 
            (void *)create_prefix(bin_ip, bin_mask));

    strcpy(ip1, "1.2.0.0");
    bin_ip = covert_ip_p_to_n(ip1);
    bin_mask = convert_dmask_to_bin_mask(16);
    mtrie_insert_prefix(&mtrie, bin_ip, ~bin_mask, 32,
                    (void *)create_prefix(bin_ip, bin_mask));

    strcpy(ip1, "5.6.7.0");
    bin_ip = covert_ip_p_to_n(ip1);
    bin_mask = convert_dmask_to_bin_mask(8);
    mtrie_insert_prefix(&mtrie, bin_ip, ~bin_mask, 32, 
                    (void *)create_prefix(bin_ip, bin_mask));

    strcpy(ip1, "100.1.2.3");
    bin_ip = covert_ip_p_to_n(ip1);
    bin_mask = convert_dmask_to_bin_mask(32);
    mtrie_insert_prefix(&mtrie, bin_ip, ~bin_mask, 32,
                    (void *)create_prefix(bin_ip, bin_mask));

    strcpy(ip1, "122.1.2.3");
    bin_ip = covert_ip_p_to_n(ip1);
    bin_mask = convert_dmask_to_bin_mask(32);
    mtrie_insert_prefix(&mtrie, bin_ip, ~bin_mask, 32,
                    (void *)create_prefix(bin_ip, bin_mask));

    strcpy(ip1, "0.0.0.1");
    bin_ip = covert_ip_p_to_n(ip1);
    bin_mask = convert_dmask_to_bin_mask(32);
    mtrie_insert_prefix(&mtrie, bin_ip, ~bin_mask, 32, 
                    (void *)create_prefix(bin_ip, bin_mask));

    strcpy(ip1, "100.50.40.1");
    bin_ip = covert_ip_p_to_n(ip1);
    bin_mask = convert_dmask_to_bin_mask(24);
    mtrie_insert_prefix(&mtrie, bin_ip, ~bin_mask, 32,
                (void *)create_prefix(bin_ip, bin_mask));

    strcpy(ip1, "1.1.1.1");
    bin_ip = covert_ip_p_to_n(ip1);
    bin_mask = convert_dmask_to_bin_mask(32);
    mtrie_insert_prefix(&mtrie, bin_ip, ~bin_mask, 32, 
                (void *)create_prefix(bin_ip, bin_mask));

    mtrie_traverse(&mtrie, ipv4_route_print );

    strcpy(ip1, "122.1.2.4");
    bin_ip = covert_ip_p_to_n(ip1);
    mtrie_node_t *node;
    assert(node = mtrie_longest_prefix_match_search(&mtrie, bin_ip));
    prefix_t *route = (prefix_t *)node->data;
    printf ("matching node = %s/%d   n_backtracks = %u   n_cmp = %u\n", 
                            covert_ip_n_to_p(route->prefix, 0), 
                            convert_bin_mask_to_dmask(route->mask),
                            node->n_backtracks, node->n_comparisons);
    return 0;
}