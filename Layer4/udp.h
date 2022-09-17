#ifndef __UDP__
#define __UDP__

#include <stdint.h>

#pragma pack (push,1)

typedef struct udp_hdr_ {

    uint16_t src_port_no;
    uint16_t dst_port_no;
    uint16_t udp_length;
    uint16_t udp_checksum;
} udp_hdr_t;

#pragma pack(pop)


uint16_t 
tcp_dump_transport_udp_protocol (
                          char *out_buff , 
                          udp_hdr_t *udp_hdr, 
                          uint16_t udp_hr_size);

#endif