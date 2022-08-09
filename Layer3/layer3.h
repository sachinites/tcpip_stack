#ifndef __LAYER3__
#define __LAYER3__

#include "../net.h"
#include "../gluethread/glthread.h"
#include "../graph.h"

#pragma pack (push,1)

/*The Ip hdr format as per the standard specification*/
typedef struct ip_hdr_{

    unsigned int version : 4 ;  /*version number, always 4 for IPv4 protocol*/    
    unsigned int ihl : 4 ;      /*length of IP hdr, in 32-bit words unit. for Ex, if this value is 5, it means length of this ip hdr is 20Bytes*/
    char tos;
    short total_length;         /*length of hdr + ip_hdr payload*/

    /* Fragmentation Related members, we shall not be using below members
     * as we will not be writing fragmentation code. if you wish, take it
     * as a extension of the project*/
    short identification;       
    unsigned int unused_flag : 1 ;
    unsigned int DF_flag : 1;   
    unsigned int MORE_flag : 1; 
    unsigned int frag_offset : 13;  


    char ttl;
    char protocol;
    short checksum;
    unsigned int src_ip;
    unsigned int dst_ip;
} ip_hdr_t;

#pragma pack(pop)


static inline void
initialize_ip_hdr(ip_hdr_t *ip_hdr){
    
    ip_hdr->version = 4;
    ip_hdr->ihl = 5; /*We will not be using option field, hence hdr size shall always be 5*4 = 20B*/
    ip_hdr->tos = 0;

    ip_hdr->total_length = 0; /*To be filled by the caller*/

    /*Fragmentation related will not be used
     * int this course, initialize them all to zero*/
    ip_hdr->identification = 0; 
    ip_hdr->unused_flag = 0;
    ip_hdr->DF_flag = 1;
    ip_hdr->MORE_flag = 0;
    ip_hdr->frag_offset = 0;

    ip_hdr->ttl = 64; /*Let us use 64*/
    ip_hdr->protocol = 0; /*To be filled by the caller*/
    ip_hdr->checksum = 0; /*Not used in this course*/
    ip_hdr->src_ip = 0; /*To be filled by the caller*/ 
    ip_hdr->dst_ip = 0; /*To be filled by the caller*/
}
#define IP_HDR_LEN_IN_BYTES(ip_hdr_ptr) (sizeof(ip_hdr_t))
#define IP_HDR_TOTAL_LEN_IN_BYTES(ip_hdr_ptr) (ip_hdr_ptr -> total_length)
#define INCREMENT_IPHDR(ip_hdr_ptr)  ((char *)ip_hdr_ptr + sizeof(ip_hdr_t))
#define IP_HDR_PAYLOAD_SIZE(ip_hdr_ptr) (ip_hdr_ptr -> total_length - sizeof(ip_hdr_t))
typedef struct rt_table_{

    glthread_t route_list;    
} rt_table_t;

typedef struct l3_route_{

    char dest[16];  /*key*/
    char mask;      /*key*/
    bool_t is_direct;    /*if set to True, then gw_ip and oif has no meaning*/
    char gw_ip[16];      /*Next hop IP*/
    char oif[IF_NAME_SIZE]; /*OIF*/
    glthread_t rt_glue;
} l3_route_t;
GLTHREAD_TO_STRUCT(rt_glue_to_l3_route, l3_route_t, rt_glue);

void
init_rt_table(rt_table_t **rt_table);

#if 0
l3_route_t *
rt_table_lookup(rt_table_t *rt_table, char *ip_addr, char mask);
#endif

void
clear_rt_table(rt_table_t *rt_table);

void
delete_rt_table_entry(rt_table_t *rt_table, char *ip_addr, char mask);

void
rt_table_add_route(rt_table_t *rt_table, 
                   char *dst, char mask,
                   char *gw, char *oif);

void
rt_table_add_direct_route(rt_table_t *rt_table,
                          char *dst, char mask);

void
dump_rt_table(rt_table_t *rt_table);

l3_route_t *
l3rib_lookup_lpm(rt_table_t *rt_table,
                 unsigned int dest_ip);

l3_route_t *
rt_table_lookup(rt_table_t *rt_table, char *ip_addr, char mask);

void
promote_pkt_to_layer3(node_t *node, interface_t *recv_intf, 
                      char *pkt, unsigned int pkt_size,
                      int L3_protocol_number);

/*import function from layer 2*/
void
demote_pkt_to_layer3(node_t *node,
                     char *pkt, unsigned int pkt_size,
                     int protocol_number, unsigned int dest_ip_addr);

#define IS_L3_ROUTES_EQUAL(rt1, rt2)              \
    ((strncmp(rt1->dest, rt2->dest, 16) == 0) &&  \
    (rt1->mask == rt2->mask) &&                   \
    (rt1->is_direct == rt2->is_direct) &&         \
    (strncmp(rt1->gw_ip, rt2->gw_ip, 16) == 0) && \
    strncmp(rt1->oif, rt2->oif, IF_NAME_SIZE) == 0)

#endif