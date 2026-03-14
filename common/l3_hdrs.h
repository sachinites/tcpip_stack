#ifndef __L3_PKT_HDRS__
#define __L3_PKT_HDRS__

#include <stdint.h>
#include <arpa/inet.h>

/*The Ip hdr format as per the standard specification*/

#pragma pack (push,1)
typedef struct ip_hdr_{

    uint8_t ver_ihl; /* Ist 4 bits is version and last 4 bits is ihl*/
    char tos;
    short total_length;         /*length of hdr + ip_hdr payload*/

    /* Fragmentation Related members, we shall not be using below members
     * as we will not be writing fragmentation code. if you wish, take it
     * as a extension of the project*/
    short identification;       

    /* unused_flag : 1 ;
        DF_flag : 1;   
        MORE_flag : 1; 
        frag_offset : 13;   */
    uint16_t flags;

    char ttl;
    char protocol;
    short checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} ip_hdr_t;

#pragma pack(pop)

static inline void
initialize_ip_hdr(ip_hdr_t *ip_hdr){
    
    ip_hdr->ver_ihl = 0x45;
    ip_hdr->tos = 0;

    ip_hdr->total_length = 0; /*To be filled by the caller*/

    /*Fragmentation related will not be used
     * int this course, initialize them all to zero*/
    ip_hdr->identification = 0; 

    uint16_t flags = (1 << 14 ); // Only DF bit is set
    ip_hdr->flags = htons(flags);

    ip_hdr->ttl = 64; /*Let us use 64*/
    ip_hdr->protocol = 0; /*To be filled by the caller*/
    ip_hdr->checksum = 0; /*Not used in this project as on 2025 Oct*/
    ip_hdr->src_ip = 0; /*To be filled by the caller*/ 
    ip_hdr->dst_ip = 0; /*To be filled by the caller*/
}

#define IP_HDR_DEFAULT_SIZE 20
#define IP_HDR_VERSION(ip_hdr_ptr) ((uint8_t) (ip_hdr_ptr->ver_ihl >> 4))
#define IP_HDR_IHL(ip_hdr_ptr) ((ip_hdr_ptr->ver_ihl & 0x0F))
#define IP_HDR_LEN_IN_BYTES(ip_hdr_ptr)  (IP_HDR_IHL(ip_hdr_ptr) * 4)
#define IP_HDR_TOTAL_LEN_IN_BYTES(ip_hdr_ptr)   (htons(ip_hdr_ptr->total_length))
#define INCREMENT_IPHDR(ip_hdr_ptr) ((c_string)ip_hdr_ptr + (IP_HDR_IHL(ip_hdr_ptr) * 4))
#define IP_HDR_PAYLOAD_SIZE(ip_hdr_ptr) (IP_HDR_TOTAL_LEN_IN_BYTES(ip_hdr_ptr) - \
        IP_HDR_LEN_IN_BYTES(ip_hdr_ptr))

#pragma pack (push,1)
typedef struct srh_hdr_ {

    uint8_t nexthdr;
    uint8_t hdrlen;
    uint8_t type;
    uint8_t segments_left;
    uint8_t first_segment;
    uint8_t flags;
    uint16_t tag;
    uint8_t segments[0][16];
    
} srh_hdr_t;
#pragma pack(pop)





#endif // __L3_PKT_HDRS__
