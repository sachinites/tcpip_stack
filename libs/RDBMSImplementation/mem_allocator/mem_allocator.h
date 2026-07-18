#ifndef __MM_ALLOCATOR__
#define __MM_ALLOCATOR__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../gluethread/glthread.h"

#pragma pack (push,1)

typedef struct block_meta_data_{

    bool is_free;
    uint32_t block_size;
    uint64_t offset;    /*offset from the start of the page*/
    uintptr_t base_address;
    uint64_t prev_block;
    uint64_t next_block;
    glthread_t pq_glue;
} block_meta_data_t;
GLTHREAD_TO_STRUCT (pq_glue_to_block_meta_data, block_meta_data_t, pq_glue);
typedef struct vm_page_hdr_ {

    uint32_t page_size;
    block_meta_data_t block;  // must be last member
} vm_page_hdr_t;

#pragma pack(pop)

#define block_addr(base_address, block_offset)  \
    ((block_offset != UINT64_MAX) ? ((block_meta_data_t *)((char *)(base_address) + block_offset)) : NULL)

void
allocator_init (void *base_address, uint32_t size);

void 
allocator_deinit (void *base_address);

void *
allocator_alloc_mem (uint32_t req_size);

uint32_t
allocator_free_mem (void *addr) ;

bool
allocator_is_vm_page_empty(void *base_address);

void
allocator_print_vm_page (void *base_address);

void 
allocator_reinit (void *base_address) ;

void 
allocator_deinit (void *base_address) ;

/* Helping Macros */
#define MM_GET_PAGE_FROM_META_BLOCK(block_meta_data_ptr)    \
    ((vm_page_hdr_t *)((char *)block_meta_data_ptr - block_meta_data_ptr->offset))

#define NEXT_META_BLOCK(block_meta_data_ptr)    \
    (block_meta_data_ptr->next_block)

#define NEXT_META_BLOCK_BY_SIZE(block_meta_data_ptr)    \
    (block_meta_data_t *)((char *)(block_meta_data_ptr + 1) \
        + block_meta_data_ptr->block_size)

#define PREV_META_BLOCK(block_meta_data_ptr)    \
    (block_meta_data_ptr->prev_block)

#define mm_bind_blocks_for_allocation(base_address, allocated_meta_block, free_meta_block)  \
    free_meta_block->prev_block = allocated_meta_block->offset;        \
    free_meta_block->next_block = \
        block_addr(base_address, allocated_meta_block->next_block) ?                             \
        block_addr(base_address, allocated_meta_block->next_block)->offset : UINT64_MAX;    \
    allocated_meta_block->next_block = free_meta_block->offset;                \
    if (free_meta_block->next_block != UINT64_MAX)  \
    block_addr(base_address, free_meta_block->next_block)->prev_block = free_meta_block->offset;

#define mm_bind_blocks_for_deallocation(base_address, freed_meta_block_down, freed_meta_block_top)    \
    freed_meta_block_down->next_block = freed_meta_block_top->next_block;               \
    if(freed_meta_block_top->next_block != UINT64_MAX)                                              \
    block_addr(base_address, freed_meta_block_top->next_block)->prev_block = freed_meta_block_down->offset

static inline int
mm_get_hard_internal_memory_frag_size(
            block_meta_data_t *first,
            block_meta_data_t *second){

    block_meta_data_t *next_block = NEXT_META_BLOCK_BY_SIZE(first);  
    return (int)((unsigned long)second - (unsigned long)(next_block));
}

static inline bool
allocator_is_vm_page_free(void *base_address);

#endif 