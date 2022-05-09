#include <stdint.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "mtrie.h"

/* This file tests the mtrie implementation for IPV4 routing table */
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

int
main(int argc, char **argv) {

    int i, j, k, l;

mtrie_t mtrie = {NULL, 0, 0, {0,0}, 0};
    
    init_mtrie(&mtrie, 32);
    uint32_t mask2 = ~0;
    bitmap_t ip, mask;
    bitmap_init (&ip, 32);
    bitmap_init (&mask, 32);
    prefix_t *prefix;
    
    for (i = 0; i < 128; i++)
    {
        for (j = 0; j < 128; j++)
        {
            for (k = 0; k < 128; k++)
            {
                for (l = 0; l < 3; l++)
                {
                    ip.bits[0] |= (i << 24);
                    ip.bits[0] |= (j << 16);
                    ip.bits[0] |= (k << 8);
                    ip.bits[0] |= l;
                    prefix = create_prefix(ip.bits[0], ~mask.bits[0]);
                    printf("Installing : %s/%d\n",covert_ip_n_to_p(ip.bits[0], 0), convert_bin_mask_to_dmask(~mask.bits[0]));
                    /*mtrie_insert_prefix(&mtrie, &ip, &mask, 32,
                                        (void *)prefix);
                    mtrie_print_ipv4_recursive(&mtrie);
                    */
                    sleep(1);
                }
            }
        }
    }
    mtrie_print_ipv4_recursive(&mtrie);
    return 0;
}

#if 0

int
main(int argc, char **argv) {

    mtrie_t mtrie = {NULL, 0, 0, {0,0}, 0};
    
    init_mtrie(&mtrie, 32);

    char ip1[16] = "1.2.3.4";
    uint8_t dmask = 24;

    uint32_t _bin_ip = covert_ip_p_to_n(ip1);
    uint32_t _bin_mask = convert_dmask_to_bin_mask(dmask);

    bitmap_t bbin_ip, bbin_mask;
    bitmap_init (&bbin_ip, 32);
    bitmap_init (&bbin_mask, 32);

/*
    printf ("Test : %s/%d\n", 
            covert_ip_n_to_p(bin_ip, 0), 
            convert_bin_mask_to_dmask(bin_mask));
*/

   // mtrie_insert_prefix(&mtrie, bin_ip, ~bin_mask, 32, 
     //                   (void *)create_prefix(bin_ip, bin_mask));

#if 0
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
#endif
    strcpy(ip1, "1.1.1.1");
    _bin_ip = covert_ip_p_to_n(ip1);
    _bin_mask = convert_dmask_to_bin_mask(32);
    memcpy(bbin_ip.bits, &_bin_ip, sizeof(_bin_ip));
    memcpy(bbin_mask.bits, &_bin_mask, sizeof(_bin_mask));
    bitmap_inverse(&bbin_mask, 32);
    mtrie_insert_prefix(&mtrie, &bbin_ip, &bbin_mask, 32, 
                (void *)create_prefix(_bin_ip, _bin_mask));

    strcpy(ip1, "1.1.1.0");
    _bin_ip = covert_ip_p_to_n(ip1);
    _bin_mask = convert_dmask_to_bin_mask(24);
    memcpy(bbin_ip.bits, &_bin_ip, sizeof(_bin_ip));
    memcpy(bbin_mask.bits, &_bin_mask, sizeof(_bin_mask));
    bitmap_inverse(&bbin_mask, 32);
    mtrie_insert_prefix(&mtrie, &bbin_ip, &bbin_mask, 32, 
                (void *)create_prefix(_bin_ip, _bin_mask));

    strcpy(ip1, "1.1.0.0");
    _bin_ip = covert_ip_p_to_n(ip1);
    _bin_mask = convert_dmask_to_bin_mask(16);
    memcpy(bbin_ip.bits, &_bin_ip, sizeof(_bin_ip));
    memcpy(bbin_mask.bits, &_bin_mask, sizeof(_bin_mask));
    bitmap_inverse(&bbin_mask, 32);
    mtrie_insert_prefix(&mtrie, &bbin_ip, &bbin_mask, 32, 
                (void *)create_prefix(_bin_ip, _bin_mask));

    strcpy(ip1, "1.0.0.0");
    _bin_ip = covert_ip_p_to_n(ip1);
    _bin_mask = convert_dmask_to_bin_mask(8);
    memcpy(bbin_ip.bits, &_bin_ip, sizeof(_bin_ip));
    memcpy(bbin_mask.bits, &_bin_mask, sizeof(_bin_mask));
    bitmap_inverse(&bbin_mask, 32);
    mtrie_insert_prefix(&mtrie, &bbin_ip, &bbin_mask, 32, 
                (void *)create_prefix(_bin_ip, _bin_mask));

    strcpy(ip1, "1.1.1.1");
    _bin_ip = covert_ip_p_to_n(ip1);
    mtrie_node_t *node;
    memcpy(bbin_ip.bits, &_bin_ip, sizeof(_bin_ip));
    assert(node = mtrie_longest_prefix_match_search(&mtrie, &bbin_ip));
    prefix_t *route = (prefix_t *)node->data;
    printf ("mtrie.N = %u, matching node = %s/%d   n_backtracks = %u   n_cmp = %u\n", 
                            mtrie.N,
                            covert_ip_n_to_p(route->prefix, 0), 
                            convert_bin_mask_to_dmask(route->mask),
                            node->n_backtracks, node->n_comparisons);

    strcpy(ip1, "1.1.1.1");
    _bin_ip = covert_ip_p_to_n(ip1);
    _bin_mask = convert_dmask_to_bin_mask(32);
    memcpy(bbin_ip.bits, &_bin_ip, sizeof(_bin_ip));
    memcpy(bbin_mask.bits, &_bin_mask, sizeof(_bin_mask));
    bitmap_inverse(&bbin_mask, 32);
    assert(node = mtrie_exact_prefix_match_search (&mtrie, &bbin_ip, &bbin_mask));
    route = (prefix_t *)node->data;
    printf ("mtrie.N = %u, exact matching node = %s/%d   n_backtracks = %u   n_cmp = %u\n", 
                            mtrie.N,
                            covert_ip_n_to_p(route->prefix, 0), 
                            convert_bin_mask_to_dmask(route->mask),
                            node->n_backtracks, node->n_comparisons);

    mtrie_print_ipv4_recursive(&mtrie);
     strcpy(ip1, "1.1.1.1");
    _bin_ip = covert_ip_p_to_n(ip1);
    _bin_mask = convert_dmask_to_bin_mask(32);
    memcpy(bbin_ip.bits, &_bin_ip, sizeof(_bin_ip));
    memcpy(bbin_mask.bits, &_bin_mask, sizeof(_bin_mask));
    bitmap_inverse(&bbin_mask, 32);
    printf ("Deleting 1.1.1.1/32\n");
    assert(mtrie_delete_prefix(&mtrie, &bbin_ip, &bbin_mask));

    strcpy(ip1, "1.1.1.0");
    _bin_ip = covert_ip_p_to_n(ip1);
    _bin_mask = convert_dmask_to_bin_mask(24);
    memcpy(bbin_ip.bits, &_bin_ip, sizeof(_bin_ip));
    memcpy(bbin_mask.bits, &_bin_mask, sizeof(_bin_mask));
    bitmap_inverse(&bbin_mask, 32);
    printf ("Deleting 1.1.1.0/24\n");
    assert(mtrie_delete_prefix(&mtrie, &bbin_ip, &bbin_mask));

    strcpy(ip1, "1.1.0.0");
    _bin_ip = covert_ip_p_to_n(ip1);
    _bin_mask = convert_dmask_to_bin_mask(16);
    memcpy(bbin_ip.bits, &_bin_ip, sizeof(_bin_ip));
    memcpy(bbin_mask.bits, &_bin_mask, sizeof(_bin_mask));
    bitmap_inverse(&bbin_mask, 32);
    printf ("Deleting 1.1.0.0/16\n");
    assert(mtrie_delete_prefix(&mtrie, &bbin_ip, &bbin_mask));

    strcpy(ip1, "1.0.0.0");
   _bin_ip = covert_ip_p_to_n(ip1);
    _bin_mask = convert_dmask_to_bin_mask(8);
    memcpy(bbin_ip.bits, &_bin_ip, sizeof(_bin_ip));
    memcpy(bbin_mask.bits, &_bin_mask, sizeof(_bin_mask));
    bitmap_inverse(&bbin_mask, 32);
    printf ("Deleting 1.0.0.0/8\n");
    assert(mtrie_delete_prefix(&mtrie, &bbin_ip, &bbin_mask));

    mtrie_print_ipv4_recursive(&mtrie);
    printf("mtrie Linear Traversal \n");
    glthread_t *curr;
    ITERATE_GLTHREAD_BEGIN(&mtrie.list_head, curr)
    {
        node = list_glue_to_mtrie_node(curr);
        route = (prefix_t *)node->data;
        printf("route = %s/%d\n",
               covert_ip_n_to_p(route->prefix, 0),
               convert_bin_mask_to_dmask(route->mask));
    }
    ITERATE_GLTHREAD_END(&mtrie.list_head, curr);
    mtrie_destroy(&mtrie);
    printf("mtrie.N = %u\n", mtrie.N);
    return 0;
}

#endif