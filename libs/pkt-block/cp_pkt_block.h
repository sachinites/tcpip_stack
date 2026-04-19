#ifndef __CP_PKT_BLOCK__
#define __CP_PKT_BLOCK__

#include <stdint.h>
#include "../common/protoIds.h"
#include "../common/cmn_struct.h"

#define CP_MAX_PACKET_BUFFER_SIZE   2048
#define CP_PKT_BUFFER_RIGHT_ROOM    128   

typedef struct cp_pkt_block_ {

    uintptr_t alloc_ptr;
    uint8_t *pkt_start;
    pkt_size_t pkt_size;
    uint16_t ref_count;
    gen_proto_id_t hdr_type;

} cp_pkt_block_t;

void
cp_pkt_block_reference(cp_pkt_block_t *pkt_block);

void
cp_pkt_block_dereference(cp_pkt_block_t *pkt_block);

uint8_t *
cp_pkt_block_get_pkt(cp_pkt_block_t *pkt_block, pkt_size_t *pkt_size) ;

void 
cp_pkt_block_slide (cp_pkt_block_t *pkt_block, 
                 int8_t lorr1, 
                 int8_t lorr2, 
                 pkt_size_t space);

cp_pkt_block_t *
cp_pkt_block_get_new_pkt_buffer (pkt_size_t pkt_size);

#endif 