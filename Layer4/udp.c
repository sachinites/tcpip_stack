#include "udp.h"

uint16_t 
tcp_dump_transport_udp_protocol (
                          char *out_buff , 
                          udp_hdr_t *udp_hdr, 
                          uint16_t udp_hr_size) {

    uint16_t rc = 0;
    rc += sprintf (out_buff + rc, "UDP Hdr : Sport : %d   Dort : %d\n", 
                            udp_hdr->src_port_no, udp_hdr->dst_port_no);
    return rc;
}