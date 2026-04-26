#include <stdlib.h>
#include <assert.h>
#include "cp_pkt_block.h"
#include "../LinuxMemoryManager/uapi_mm.h"

void
cp_pkt_block_reference(cp_pkt_block_t *pkt_block) { 
    pkt_block->ref_count++; 
}

void
cp_pkt_block_dereference(cp_pkt_block_t *pkt_block) {

    assert (pkt_block->ref_count);
    pkt_block->ref_count--;
    if (pkt_block->ref_count) return;
    XFREE(pkt_block->alloc_ptr);
    XFREE(pkt_block);
}

uint8_t *
cp_pkt_block_get_pkt(cp_pkt_block_t *pkt_block, pkt_size_t *pkt_size) {

    if (pkt_size) *pkt_size = pkt_block->pkt_size;
    return pkt_block->pkt_start;
}

void 
cp_pkt_block_slide (cp_pkt_block_t *pkt_block, 
                    int8_t lorr1, 
                    int8_t lorr2, 
                    pkt_size_t space) {
    
    assert(lorr1 == -1 || lorr1 == 1);
    assert(lorr2 == -1 || lorr2 == 1);
    
    uint8_t *pkt;
    pkt_size_t pkt_size;

    assert(pkt_block->alloc_ptr);

    pkt = (uint8_t *)cp_pkt_block_get_pkt(pkt_block, &pkt_size);

    switch (lorr1) {

        case -1:
            switch (lorr2) {
                case -1:
                    pkt      -= space;
                    pkt_size += space;
                    break;
                case 1:
                    pkt      += space;
                    pkt_size -= space;
                    break;
            }
            break;

        case 1:
            switch (lorr2) {
                case -1:
                    pkt_size -= space;
                    break;
                case 1:
                    pkt_size += space;
                    break;
            }
            break;
    }

    if (lorr1 == -1) pkt_block->pkt_start = pkt;
    pkt_block->pkt_size = pkt_size;    
}

cp_pkt_block_t *
cp_pkt_block_get_new_pkt_buffer (pkt_size_t pkt_size) {

    cp_pkt_block_t *pkt_block = (cp_pkt_block_t *)XCALLOC2(0, 1, cp_pkt_block_t);
    pkt_block->alloc_ptr = (uint8_t *)XCALLOC_BUFF(0, CP_MAX_PACKET_BUFFER_SIZE);
    pkt_block->pkt_start       = (uint8_t *)
        (pkt_block->alloc_ptr +
         CP_MAX_PACKET_BUFFER_SIZE - (pkt_size + CP_PKT_BUFFER_RIGHT_ROOM));
    pkt_block->pkt_size  = pkt_size;
    pkt_block->ref_count = 1;
    pkt_block->hdr_type = ETHERNET_HEADER;
    return pkt_block;
}