#include <assert.h>
#include <memory.h>
#include <stdlib.h>
#include "mem_allocator.h"

glthread_t free_block_list_head = {NULL, NULL};

static int
free_blocks_comparison_function(
        void *_block_meta_data1,
        void *_block_meta_data2){

    block_meta_data_t *block_meta_data1 = 
        (block_meta_data_t *)_block_meta_data1;

    block_meta_data_t *block_meta_data2 = 
        (block_meta_data_t *)_block_meta_data2;

    if(block_meta_data1->block_size > block_meta_data2->block_size)
        return -1;
    else if(block_meta_data1->block_size < block_meta_data2->block_size)
        return 1;
    return 0;
}

static void 
meta_block_init (block_meta_data_t *block) {

    block->is_free = true;
    block->block_size = 0;
    block->offset = UINT64_MAX;
    block->base_address = 0;
    block->prev_block = UINT64_MAX;
    block->next_block = UINT64_MAX;
    init_glthread (&block->pq_glue);
}

static void
mm_union_free_blocks(
        char *base_address,
        block_meta_data_t *first,
        block_meta_data_t *second){

    assert(first->is_free == true &&
                second->is_free == true);

    remove_glthread(&first->pq_glue);
    remove_glthread(&second->pq_glue);
    mm_bind_blocks_for_deallocation(base_address, first, second);
}

static void
allocator_add_block_to_free_block_list(
        block_meta_data_t *free_block){

    assert (free_block->is_free == true);
    glthread_priority_insert(&free_block_list_head, 
            &free_block->pq_glue,
            free_blocks_comparison_function,
             (size_t)&(((block_meta_data_t *)0)->pq_glue));
}

void
allocator_init (void *base_address, uint32_t size) {

    vm_page_hdr_t *vm_page_hdr = (vm_page_hdr_t *)base_address;
    vm_page_hdr->page_size = size;
    vm_page_hdr->block.is_free = true;
    meta_block_init (&vm_page_hdr->block);
    vm_page_hdr->block.block_size = size - sizeof(vm_page_hdr_t);
    vm_page_hdr->block.offset = offsetof(vm_page_hdr_t, block);
    vm_page_hdr->block.base_address = (uintptr_t)base_address;
    vm_page_hdr->block.prev_block = UINT64_MAX;
    vm_page_hdr->block.next_block = UINT64_MAX;
    allocator_add_block_to_free_block_list(&vm_page_hdr->block);
}

/* Restart the memory mgmt of this VM page again*/
void 
allocator_reinit (void *base_address) {

    uint64_t block_itr;
    block_meta_data_t *block;

    vm_page_hdr_t *vm_page_hdr = (vm_page_hdr_t *)base_address;

    /* Iterarate over all free meta blocks and fix up their base_address  and queue them
        in global free block list*/
    for (block_itr = vm_page_hdr->block.offset;
            block_itr != UINT64_MAX;
            block_itr = block_addr (base_address, block_itr)->next_block) {

        block = block_addr (base_address, block_itr);
        assert (block->base_address == 0);
        block->base_address = (uintptr_t)base_address;
        
        if (block->is_free) {
            allocator_add_block_to_free_block_list(block);
        }
    }
}

void 
allocator_deinit (void *base_address) {

    uint64_t block_itr;
    block_meta_data_t *block;

    vm_page_hdr_t *vm_page_hdr = (vm_page_hdr_t *)base_address;
    
    for (block_itr = vm_page_hdr->block.offset;
            block_itr != UINT64_MAX;
            block_itr = block_addr (base_address, block_itr)->next_block) {

        block = block_addr (base_address, block_itr);
        assert ( block->base_address == (uintptr_t) base_address ); 
        block->base_address = 0;

        if (block->is_free) {
            remove_glthread (&block->pq_glue);
        }
    }
}

static bool
allocator_split_free_data_block_for_allocation (
            char *base_address,
            vm_page_hdr_t *vm_page,
            block_meta_data_t *block_meta_data,
            uint32_t size){

    block_meta_data_t *next_block_meta_data = NULL;

    assert(block_meta_data->is_free);

    if (block_meta_data->block_size < size ){
        return false;
    }

    uint32_t remaining_size =
        block_meta_data->block_size - size;

    block_meta_data->is_free = false;
    block_meta_data->block_size = size;

    /* Since this block of memory is going to be allocated to the application, 
     * remove it from priority list of free blocks*/
    remove_glthread (&block_meta_data->pq_glue);
    
    /*Case 1 : No Split*/
    if(!remaining_size){
        return true;
    }

    if (remaining_size < sizeof(block_meta_data_t)) {
        return true;
    }

    /*New Meta block is to be created*/
    next_block_meta_data = NEXT_META_BLOCK_BY_SIZE(block_meta_data);
    meta_block_init (next_block_meta_data);
    next_block_meta_data->is_free = true;
    next_block_meta_data->block_size =
        remaining_size - sizeof(block_meta_data_t);
    next_block_meta_data->offset = block_meta_data->offset +
                                   sizeof(block_meta_data_t) + block_meta_data->block_size;
     next_block_meta_data->base_address = (uintptr_t)base_address;
    allocator_add_block_to_free_block_list(next_block_meta_data);
    mm_bind_blocks_for_allocation(base_address, block_meta_data, next_block_meta_data);
    return true;
}

void *
allocator_alloc_mem (uint32_t req_size) {

    glthread_t *curr;
    curr = dequeue_glthread_first(&free_block_list_head);
    if (!curr) return NULL;
    block_meta_data_t *block_meta_data = pq_glue_to_block_meta_data(curr);
    assert(block_meta_data->is_free);
    if (block_meta_data->block_size < req_size) return NULL;
    if (!allocator_split_free_data_block_for_allocation(
            (char *)block_meta_data->base_address, 
            (vm_page_hdr_t *)block_meta_data->base_address, 
            block_meta_data, req_size)) {
        return NULL;
    }
    memset((char *)(block_meta_data + 1), 0, block_meta_data->block_size);
    return (void *)(block_meta_data + 1);
}

static uint32_t
allocator_free_block (char *base_address, block_meta_data_t *to_be_free_block) {

    block_meta_data_t *return_block;

    return_block = to_be_free_block;

    assert(!to_be_free_block->is_free);
    
    vm_page_hdr_t *vm_page = 
        MM_GET_PAGE_FROM_META_BLOCK(to_be_free_block);
   
    to_be_free_block->is_free = true;
    
    block_meta_data_t *next_block = 
        block_addr(base_address, NEXT_META_BLOCK(to_be_free_block));

    /*Handling Hard IF memory*/
    if(next_block){
        /*Scenario 1 : When data block to be freed is not the last 
         * upper most meta block in a VM data page*/
        to_be_free_block->block_size += 
            mm_get_hard_internal_memory_frag_size (
                    to_be_free_block, next_block);
    }
    else {
        /* Scenario 2: Page Boundary condition*/
        /* Block being freed is the upper most free data block
         * in a VM data page, check of hard internal fragmented 
         * memory and merge*/
        char *end_address_of_vm_page = (char *)((char *)vm_page + vm_page->page_size);
        char *end_address_of_free_data_block = 
            (char *)(to_be_free_block + 1) + to_be_free_block->block_size;
        int internal_mem_fragmentation = (int)((unsigned long)end_address_of_vm_page - 
                (unsigned long)end_address_of_free_data_block);
        to_be_free_block->block_size += internal_mem_fragmentation;
    }
    
    /*Now perform Merging*/
    if(next_block && next_block->is_free){

        to_be_free_block->block_size += 
            next_block->block_size + sizeof(block_meta_data_t);
        /*Union two free blocks*/
        mm_union_free_blocks(base_address, to_be_free_block, next_block);
        return_block = to_be_free_block;
    }

    /*Check the previous block if it was free*/
    block_meta_data_t *prev_block = 
        block_addr(base_address, PREV_META_BLOCK(to_be_free_block));
    
    if(prev_block && prev_block->is_free){
        
        prev_block->block_size += 
            to_be_free_block->block_size + sizeof(block_meta_data_t);
        mm_union_free_blocks(base_address, prev_block, to_be_free_block);
        return_block = prev_block;
    }
   
    allocator_add_block_to_free_block_list(return_block);
    return return_block->block_size;
}

uint32_t
allocator_free_mem (void *addr) {

    block_meta_data_t *block_meta_data = 
        (block_meta_data_t *)((char *)addr - sizeof(block_meta_data_t));
    
    assert(!block_meta_data->is_free);
    return allocator_free_block((char *)block_meta_data->base_address, block_meta_data);
}

bool
allocator_is_vm_page_empty (void *base_address) {

    glthread_t *curr;

    vm_page_hdr_t *vm_page = (vm_page_hdr_t *)base_address;

    if ((vm_page->page_size !=
         (vm_page->block.block_size +
          sizeof(block_meta_data_t) +
          sizeof(vm_page->page_size)))
        ||
        !vm_page->block.is_free) {

        return false;
    }

    curr = glthread_get_next (&free_block_list_head);

    if (!curr) return false;

    block_meta_data_t *block_meta_data = pq_glue_to_block_meta_data(curr);
       
    if (block_meta_data != &vm_page->block) return false;

    if (glthread_get_next (&block_meta_data->pq_glue)) {
        return false;
    }

    return true;
}

void
allocator_print_vm_page (void *base_address) {

}

#if 0
int
main(int argc, char **argv) {

    void *base_address = (void *)calloc (1, 1024);
    allocator_init(base_address, 1024);

    void *ptr1 = allocator_alloc_mem(base_address, 48);
    void *ptr2 = allocator_alloc_mem(base_address, 98);
    void *ptr3 = allocator_alloc_mem(base_address, 198);
    allocator_free_mem(base_address, ptr1);
    allocator_free_mem(base_address, ptr2);
    allocator_free_mem(base_address, ptr3);
    assert(allocator_is_vm_page_empty(base_address));
    free(base_address);
    return 0;
}
#endif
