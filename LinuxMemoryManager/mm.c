/*
 * =====================================================================================
 *
 *       Filename:  mm.c
 *
 *    Description:  This file implements the routine for Memory Manager 
 *
 *        Version:  1.0
 *        Created:  01/30/2020 10:31:41 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Juniper Networks (https://www.csepracticals.com), sachinites@gmail.com
 *        Company:  Juniper Networks
 *
 *        This file is part of the Linux Memory Manager distribution (https://github.com/sachinites) 
 *        Copyright (c) 2019 Abhishek Sagar.
 *        This program is free software: you can redistribute it and/or modify it under the terms of the GNU General 
 *        Public License as published by the Free Software Foundation, version 3.
 *        
 *        This program is distributed in the hope that it will be useful, but
 *        WITHOUT ANY WARRANTY; without even the implied warranty of
 *        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *        General Public License for more details.
 *
 *        visit website : https://www.csepracticals.com for more courses and projects
 *                                  
 * =====================================================================================
 */

#include "mm.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h> /*for getpagesize*/
#include <sys/mman.h>
#include <errno.h>
#include "css.h"

#define __USE_MMAP__
#undef __USE_BRK__
#undef __USE_GLIBC__

static vm_page_for_families_t *first_vm_page_for_families = NULL;
static vm_page_family_t misc_vm_page_family;
static size_t SYSTEM_PAGE_SIZE = 0;
void *gb_hsba = NULL;
static vm_page_t *vm_page_mm_instance = NULL;
static mm_instance_t *next_mm_instance = NULL;

void
mm_init(){

    if (!SYSTEM_PAGE_SIZE) 
        SYSTEM_PAGE_SIZE =  getpagesize() * 2;
    gb_hsba = sbrk(0);
    misc_vm_page_family.first_page = NULL;
    memset(&misc_vm_page_family, 0, sizeof(vm_page_family_t));
    strncpy(misc_vm_page_family.struct_name, "Misc" , 4);
    misc_vm_page_family.struct_size = 0;
    init_glthread(&misc_vm_page_family.free_block_priority_list_head);
}

static inline uint32_t
mm_max_page_allocatable_memory(int units){

    return (uint32_t)
        ((SYSTEM_PAGE_SIZE * units) - offset_of(vm_page_t, page_memory));
}

#define MAX_PAGE_ALLOCATABLE_MEMORY(units) \
    (mm_max_page_allocatable_memory(units))

static vm_page_t *
mm_get_available_page_index(vm_page_family_t *vm_page_family){

    vm_page_t *curr, *prev;
    int page_index = -1;

    if(!vm_page_family->first_page)
        return NULL;

    ITERATE_VM_PAGE_BEGIN(vm_page_family, curr){

        if((int)(curr->page_index) == page_index + 1){
            page_index++;
            prev = curr;
            continue;
        }
        return curr->prev;
    } ITERATE_VM_PAGE_END(vm_page_family, curr)

    return prev;
}

static vm_page_t *
mm_sbrk_get_available_page_from_heap_segment(int units){

    vm_page_t *vm_page_curr = NULL;
    
    vm_page_t *first_vm_page = (vm_page_t *)gb_hsba;

    ITERATE_HEAP_SEGMENT_PAGE_WISE_BEGIN(first_vm_page, vm_page_curr){
        if(mm_is_vm_page_empty(vm_page_curr)){
            return vm_page_curr;
        }
    }ITERATE_HEAP_SEGMENT_PAGE_WISE_END(first_vm_page, vm_page_curr);
    /*No free Page could be found, expand heap segment*/
    vm_page_curr = (vm_page_t *)sbrk(SYSTEM_PAGE_SIZE * units);

    if(!vm_page_curr){
        printf("Error : Heap Segment Expansion Failed, error no = %d\n", errno);
    }
    return vm_page_curr;
}

static vm_page_t *
mm_get_new_vm_page_from_kernel(int units){

    vm_page_t *vm_page = NULL;

#ifdef __USE_GLIBC__
    vm_page = (vm_page_t *)calloc(units, SYSTEM_PAGE_SIZE);

#elif defined(__USE_MMAP__)
    char * region = mmap(
            sbrk(0), 
            units * SYSTEM_PAGE_SIZE,
            PROT_READ|PROT_WRITE|PROT_EXEC,
            MAP_ANON|MAP_PRIVATE,
            0,0);

    if (region == MAP_FAILED) {
        printf("Error : VM Page allocation Failed\n");
        return NULL;
    }
    vm_page = (vm_page_t *)region;

#elif defined(__USE_BRK__)
    vm_page = mm_sbrk_get_available_page_from_heap_segment(units);;

#endif
    memset(vm_page, 0, units * SYSTEM_PAGE_SIZE);
    vm_page->page_size = units * SYSTEM_PAGE_SIZE;
    return vm_page;
}


mm_instance_t *
mm_init_new_instance() {

    vm_page_t *vm_page = NULL;
    
    if (!SYSTEM_PAGE_SIZE) 
        SYSTEM_PAGE_SIZE =  getpagesize() * 2;

    if (vm_page_mm_instance == NULL) {
        vm_page = mm_get_new_vm_page_from_kernel(1);
    }

    if (next_mm_instance == NULL) {
        next_mm_instance = (mm_instance_t *)(vm_page);
        next_mm_instance->gb_hsba = sbrk(0);
        return next_mm_instance;
    }

    if ((char *)(next_mm_instance + 1) == 
            (char *)vm_page + SYSTEM_PAGE_SIZE) {
        assert(0);
    }

    next_mm_instance++;
    next_mm_instance->gb_hsba = sbrk(0);
    return next_mm_instance;
}

static void
mm_sbrk_free_vm_page(vm_page_t *vm_page, int units){

    /* If this VM page is the top-most page of Heap Memory
     * Segment, then lower down the heap memory segment.
     * Note that, once you lower down the heap memory segment
     * this page shall be out of allotted valid virtual address
     * of a process, and any access to it shall result in
     * segmentation fault*/
    /* Also note that, if the VM page is the top-most page of Heap Memory
     * then it could be possible there are free contiguous pages below
     * this VM page. We need to lowered down break pointer freeing all
     * contiguous VM pages lying below this VM page*/

    if((void *)vm_page !=
            (void *)((char *)sbrk(0) - (SYSTEM_PAGE_SIZE * units))){
        return;
    }

    vm_page_t *bottom_most_free_page = NULL;

    for(bottom_most_free_page =
            MM_GET_NEXT_CONTIGUOUS_PAGE_IN_HEAP_SEGMENT(vm_page, '-');
            mm_is_vm_page_empty(bottom_most_free_page);
            bottom_most_free_page =
            MM_GET_NEXT_CONTIGUOUS_PAGE_IN_HEAP_SEGMENT(bottom_most_free_page, '-')){

        if((void *)bottom_most_free_page == gb_hsba)
            break;
    }

    if((void *)bottom_most_free_page != gb_hsba){
        bottom_most_free_page =
            MM_GET_NEXT_CONTIGUOUS_PAGE_IN_HEAP_SEGMENT(bottom_most_free_page, '+');
    }
    /*Now lower down the break pointer*/
    assert(!brk((void *)bottom_most_free_page));
}

static void
mm_return_vm_page_to_kernel(void *ptr, int units){

 int rc = 0;
MARK_VM_PAGE_EMPTY(((vm_page_t *)ptr));

#ifdef __USE_GLIBC__
    free(ptr); 
#elif defined(__USE_MMAP__)
    if(rc = munmap(ptr, units * SYSTEM_PAGE_SIZE)){
        printf("Error : Could not munmap VM page (%u) to kernel, errno = %d\n", ((vm_page_t *)ptr)->page_size, errno);
    }
#elif defined(__USE_BRK__)
    mm_sbrk_free_vm_page((vm_page_t *)ptr, units);
#endif
}

/*Return a fresh new virtual page*/
vm_page_t *
allocate_vm_page(vm_page_family_t *vm_page_family, int units){

    vm_page_t *prev_page = 
        mm_get_available_page_index(vm_page_family);

    vm_page_t *vm_page = mm_get_new_vm_page_from_kernel(units);
    vm_page->block_meta_data.is_free = MM_TRUE;
    vm_page->block_meta_data.block_size = 
        MAX_PAGE_ALLOCATABLE_MEMORY(units);
    vm_page->block_meta_data.offset =  
        offset_of(vm_page_t, block_meta_data);
    init_glthread(&vm_page->block_meta_data.priority_thread_glue);
    vm_page->block_meta_data.prev_block = NULL;
    vm_page->block_meta_data.next_block = NULL;
    vm_page->next = NULL;
    vm_page->prev = NULL;
    vm_page_family->no_of_system_calls_to_alloc_dealloc_vm_pages++;
    vm_page->pg_family = vm_page_family;

    if(!prev_page){
        vm_page->page_index = 0;
        vm_page->next = vm_page_family->first_page;
        if(vm_page_family->first_page)
            vm_page_family->first_page->prev = vm_page;
        vm_page_family->first_page = vm_page;
        return vm_page;
    }

    vm_page->next = prev_page->next;
    vm_page->prev = prev_page;
    if(vm_page->next)
        vm_page->next->prev = vm_page;
    prev_page->next = vm_page;
    vm_page->page_index = prev_page->page_index + 1;
    return vm_page;
}


void
mm_instantiate_new_page_family(
    mm_instance_t *mm_inst,
    char *struct_name,
    uint32_t struct_size){

    vm_page_family_t *vm_page_family_curr = NULL;
    vm_page_for_families_t *new_vm_page_for_families = NULL;
    vm_page_for_families_t *vm_page_for_families_global;

    vm_page_for_families_global = mm_inst ?
        mm_inst->first_vm_page_for_families : first_vm_page_for_families;

    if(!vm_page_for_families_global){
        vm_page_for_families_global = (vm_page_for_families_t *)mm_get_new_vm_page_from_kernel(1);
        vm_page_for_families_global->next = NULL;
        strncpy(vm_page_for_families_global->vm_page_family[0].struct_name, struct_name,
            MM_MAX_STRUCT_NAME);
        vm_page_for_families_global->vm_page_family[0].struct_size = struct_size;
        vm_page_for_families_global->vm_page_family[0].first_page = NULL;
        init_glthread(&vm_page_for_families_global->vm_page_family[0].free_block_priority_list_head);
        if (mm_inst) 
            mm_inst->first_vm_page_for_families = vm_page_for_families_global;
        else 
            first_vm_page_for_families =  vm_page_for_families_global;
    
        return;
    }

	vm_page_family_curr = lookup_page_family_by_name(mm_inst, struct_name);

	if(vm_page_family_curr) {
		assert(0);
	}     

    uint32_t count = 0;
    
    ITERATE_PAGE_FAMILIES_BEGIN(vm_page_for_families_global, vm_page_family_curr){

		count++;

    } ITERATE_PAGE_FAMILIES_END(vm_page_for_families_global, vm_page_family_curr);

    if(count == MAX_FAMILIES_PER_VM_PAGE){
        /*Request a new vm page from kernel to add a new family*/
        new_vm_page_for_families = (vm_page_for_families_t *)mm_get_new_vm_page_from_kernel(1);
        new_vm_page_for_families->next = vm_page_for_families_global;
        vm_page_for_families_global = new_vm_page_for_families;
        vm_page_family_curr = &vm_page_for_families_global->vm_page_family[0];
    }

    strncpy(vm_page_family_curr->struct_name, struct_name,
            MM_MAX_STRUCT_NAME);
    vm_page_family_curr->struct_size = struct_size;
    vm_page_family_curr->first_page = NULL;
    init_glthread(&vm_page_family_curr->free_block_priority_list_head);
}

vm_page_family_t *
lookup_page_family_by_name(mm_instance_t *mm_inst, char *struct_name){

    vm_page_family_t *vm_page_family_curr = NULL;
    vm_page_for_families_t *vm_page_for_families_curr = NULL;

    for(vm_page_for_families_curr = 
        mm_inst ? mm_inst->first_vm_page_for_families :        first_vm_page_for_families; 
            vm_page_for_families_curr; 
            vm_page_for_families_curr = vm_page_for_families_curr->next){

        ITERATE_PAGE_FAMILIES_BEGIN(vm_page_for_families_curr, vm_page_family_curr){

            if(strncmp(vm_page_family_curr->struct_name,
                        struct_name,
                        MM_MAX_STRUCT_NAME) == 0){

                return vm_page_family_curr;
            }
        } ITERATE_PAGE_FAMILIES_END(vm_page_for_families_curr, vm_page_family_curr);
    }
    return NULL;
}

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
mm_add_free_block_meta_data_to_free_block_list(
        vm_page_family_t *vm_page_family, 
        block_meta_data_t *free_block){

    assert(free_block->is_free == MM_TRUE);
    glthread_priority_insert(&vm_page_family->free_block_priority_list_head, 
            &free_block->priority_thread_glue,
            free_blocks_comparison_function,
            offset_of(block_meta_data_t, priority_thread_glue));
}

static vm_page_t *
mm_family_new_page_add(vm_page_family_t *vm_page_family, int units){

    vm_page_t *vm_page = allocate_vm_page(vm_page_family, units);

    if(!vm_page)
        return NULL;

    /* The new page is like one free block, add it to the
     * free block list*/
    mm_add_free_block_meta_data_to_free_block_list(
        vm_page_family, &vm_page->block_meta_data);

    return vm_page;
}

/* Fn to mark block_meta_data as being Allocated for
 * 'size' bytes of application data. Return TRUE if 
 * block allocation succeeds*/

static vm_bool_t
mm_split_free_data_block_for_allocation(
            vm_page_family_t *vm_page_family,
            block_meta_data_t *block_meta_data,
            uint32_t size){

    block_meta_data_t *next_block_meta_data = NULL;

    assert(block_meta_data->is_free == MM_TRUE);

    if(block_meta_data->block_size < size){
        return MM_FALSE;
    }

    uint32_t remaining_size =
        block_meta_data->block_size - size;

    block_meta_data->is_free = MM_FALSE;
    block_meta_data->block_size = size;

    /*Unchanged*/
    /*block_meta_data->offset =  ??*/

    /* Since this block of memory is going to be allocated to the application, 
     * remove it from priority list of free blocks*/
    remove_glthread(&block_meta_data->priority_thread_glue);
    
    vm_page_family->total_memory_in_use_by_app +=
            sizeof(block_meta_data_t) + size;

    /*Case 1 : No Split*/
    if(!remaining_size){
        /*No need to repair linkages, they do not change*/
        //mm_bind_blocks_for_allocation(block_meta_data, next_block_meta_data);
        return MM_TRUE;
    }

    /*Case 3 : Partial Split : Soft Internal Fragmentation*/
    else if(sizeof(block_meta_data_t) < remaining_size && 
        remaining_size < (sizeof(block_meta_data_t) + vm_page_family->struct_size)){
        /*New Meta block is to be created*/
        next_block_meta_data = NEXT_META_BLOCK_BY_SIZE(block_meta_data);
        next_block_meta_data->is_free = MM_TRUE;
        next_block_meta_data->block_size =
            remaining_size - sizeof(block_meta_data_t);
        next_block_meta_data->offset = block_meta_data->offset +
            sizeof(block_meta_data_t) + block_meta_data->block_size;
        init_glthread(&next_block_meta_data->priority_thread_glue);
        mm_add_free_block_meta_data_to_free_block_list(
                vm_page_family, next_block_meta_data);
        mm_bind_blocks_for_allocation(block_meta_data, next_block_meta_data);
    }

    /*Case 3 : Partial Split : Hard Internal Fragmentation*/
    else if(remaining_size < sizeof(block_meta_data_t)){
        //next_block_meta_data = block_meta_data->next_block;
        /*No need to repair linkages, they do not change*/
        //mm_bind_blocks_for_allocation(block_meta_data, next_block_meta_data);
    }

    /*Case 2 : Full Split  : New Meta block is Created*/
    else {
        /*New Meta block is to be created*/
        next_block_meta_data = NEXT_META_BLOCK_BY_SIZE(block_meta_data);
        next_block_meta_data->is_free = MM_TRUE;
        next_block_meta_data->block_size =
            remaining_size - sizeof(block_meta_data_t);
        next_block_meta_data->offset = block_meta_data->offset +
            sizeof(block_meta_data_t) + block_meta_data->block_size;
        init_glthread(&next_block_meta_data->priority_thread_glue);
        mm_add_free_block_meta_data_to_free_block_list(
                vm_page_family, next_block_meta_data);
        mm_bind_blocks_for_allocation(block_meta_data, next_block_meta_data);
    }

    return MM_TRUE;
}

static block_meta_data_t *
mm_allocate_free_data_block(
        vm_page_family_t *vm_page_family,
        uint32_t req_size){ 

    vm_bool_t status = MM_FALSE;
    vm_page_t *vm_page = NULL;
    block_meta_data_t *block_meta_data = NULL;

    int n_pages_required = ( req_size / MAX_PAGE_ALLOCATABLE_MEMORY(1)) + 1;

    block_meta_data_t *biggest_block_meta_data = 
        mm_get_biggest_free_block_page_family(vm_page_family); 

    if(!biggest_block_meta_data || 
        biggest_block_meta_data->block_size < req_size){

        /*Time to add a new page to Page family to satisfy the request*/
        vm_page = mm_family_new_page_add(vm_page_family, n_pages_required);

        /*Allocate the free block from this page now*/
        status = mm_split_free_data_block_for_allocation(vm_page_family, 
                    &vm_page->block_meta_data, req_size);

        if(status)
            return &vm_page->block_meta_data;

        return NULL;
    }
    /*Step 3*/
    /*The biggest block meta data can satisfy the request*/
    if(biggest_block_meta_data){
        status = mm_split_free_data_block_for_allocation(vm_page_family, 
                biggest_block_meta_data, req_size);
    }

    if(status)
        return biggest_block_meta_data;
    
    return NULL;
}

/* The public fn to be invoked by the application for Dynamic 
 * Memory Allocations.*/
void *
xcalloc(mm_instance_t *mm_inst, char *struct_name, int units){

    /*Step 1*/
    vm_page_family_t *pg_family = 
        lookup_page_family_by_name(mm_inst, struct_name);

    if(!pg_family){
        
        printf("Error : Structure %s not registered with Memory Manager\n",
            struct_name);
        assert(0);
        return NULL;
    }
    
    /*Find the page which can satisfy the request*/
    block_meta_data_t *free_block_meta_data = NULL;
    
    free_block_meta_data = mm_allocate_free_data_block(
                            pg_family, units * pg_family->struct_size);

    if(free_block_meta_data){
        memset((char *)(free_block_meta_data + 1), 0, free_block_meta_data->block_size);
        return  (void *)(free_block_meta_data + 1);
    }

    return NULL;
}

static int 
mm_get_hard_internal_memory_frag_size(
            block_meta_data_t *first,
            block_meta_data_t *second){

    block_meta_data_t *next_block = NEXT_META_BLOCK_BY_SIZE(first);  
    return (int)((unsigned long)second - (unsigned long)(next_block));
}

static void
mm_union_free_blocks(block_meta_data_t *first,
        block_meta_data_t *second){

    assert(first->is_free == MM_TRUE &&
        second->is_free == MM_TRUE);
    remove_glthread(&first->priority_thread_glue);
    remove_glthread(&second->priority_thread_glue);
    mm_bind_blocks_for_deallocation(first, second);
}

void
mm_vm_page_delete_and_free(
        vm_page_t *vm_page){

    vm_page_family_t *vm_page_family = 
        vm_page->pg_family;

    assert(vm_page_family->first_page);

    if(vm_page_family->first_page == vm_page){
        vm_page_family->first_page = vm_page->next;
        if(vm_page->next)
            vm_page->next->prev = NULL;
        vm_page_family->no_of_system_calls_to_alloc_dealloc_vm_pages++;
        vm_page->next = NULL;
        vm_page->prev = NULL;
        mm_return_vm_page_to_kernel((void *)vm_page, 
                    vm_page->page_size / SYSTEM_PAGE_SIZE);
        return;
    }

    if(vm_page->next)
        vm_page->next->prev = vm_page->prev;
    vm_page->prev->next = vm_page->next;
    vm_page_family->no_of_system_calls_to_alloc_dealloc_vm_pages++;
    mm_return_vm_page_to_kernel((void *)vm_page, vm_page->page_size / SYSTEM_PAGE_SIZE);
}

static block_meta_data_t *
mm_free_blocks(block_meta_data_t *to_be_free_block){

    block_meta_data_t *return_block = NULL;

    assert(to_be_free_block->is_free == MM_FALSE);
    
    vm_page_t *hosting_page = 
        MM_GET_PAGE_FROM_META_BLOCK(to_be_free_block);

    vm_page_family_t *vm_page_family = hosting_page->pg_family;

    return_block = to_be_free_block;
    
    to_be_free_block->is_free = MM_TRUE;
    
    block_meta_data_t *next_block = NEXT_META_BLOCK(to_be_free_block);

    /*Handling Hard IF memory*/
    if(next_block){
        /*Scenario 1 : When data block to be freed is not the last 
         * upper most meta block in a VM data page*/
        to_be_free_block->block_size += 
            mm_get_hard_internal_memory_frag_size (to_be_free_block, next_block);
    }
    else {
        /* Scenario 2: Page Boundry condition*/
        /* Block being freed is the upper most free data block
         * in a VM data page, check of hard internal fragmented 
         * memory and merge*/
        char *end_address_of_vm_page = (char *)((char *)hosting_page + hosting_page->page_size);
        char *end_address_of_free_data_block = 
            (char *)(to_be_free_block + 1) + to_be_free_block->block_size;
        int internal_mem_fragmentation = (int)((unsigned long)end_address_of_vm_page - 
                (unsigned long)end_address_of_free_data_block);
        to_be_free_block->block_size += internal_mem_fragmentation;
    }
    
    /*Now perform Merging*/
    if(next_block && next_block->is_free == MM_TRUE){
        /*Union two free blocks*/
        mm_union_free_blocks(to_be_free_block, next_block);
        return_block = to_be_free_block;
    }
    /*Check the previous block if it was free*/
    block_meta_data_t *prev_block = PREV_META_BLOCK(to_be_free_block);
    
    if(prev_block && prev_block->is_free){
        mm_union_free_blocks(prev_block, to_be_free_block);
        return_block = prev_block;
    }
   
    if(mm_is_vm_page_empty(hosting_page)){
        mm_vm_page_delete_and_free(hosting_page);
        return NULL;
    }
    mm_add_free_block_meta_data_to_free_block_list(
            hosting_page->pg_family, return_block);
    
    return return_block;
}

void
xfree(void *app_data){

    block_meta_data_t *block_meta_data = 
        (block_meta_data_t *)((char *)app_data - sizeof(block_meta_data_t));
    
    assert(block_meta_data->is_free == MM_FALSE);
    mm_free_blocks(block_meta_data);
}

vm_bool_t
mm_is_vm_page_empty(vm_page_t *vm_page){

    if(vm_page->block_meta_data.next_block == NULL && 
        vm_page->block_meta_data.prev_block == NULL &&
        vm_page->block_meta_data.is_free == MM_TRUE){

        return MM_TRUE;
    }
    return MM_FALSE;
}

void
mm_print_vm_page_details(vm_page_t *vm_page, uint32_t i){

    printf("\tPage Index : %u \n", vm_page->page_index);
    printf("\t\t next = %p, prev = %p\n", vm_page->next, vm_page->prev);
    printf("\t\t page family = %s, page_size = %uB\n", 
        vm_page->pg_family->struct_name, vm_page->page_size);

    uint32_t j = 0;
    block_meta_data_t *curr;
    ITERATE_VM_PAGE_ALL_BLOCKS_BEGIN(vm_page, curr){

        printf(ANSI_COLOR_YELLOW "\t\t\t%-14p Block %-3u %s  block_size = %-6u  "
                "offset = %-6u  prev = %-14p  next = %p\n"
                ANSI_COLOR_RESET, curr,
                j++, curr->is_free ? "F R E E D" : "ALLOCATED",
                curr->block_size, curr->offset, 
                curr->prev_block,
                curr->next_block);
    } ITERATE_VM_PAGE_ALL_BLOCKS_END(vm_page, curr);
}

void
mm_print_memory_usage(mm_instance_t *mm_inst,  char *struct_name){

    uint32_t i = 0;
    vm_page_t *vm_page = NULL;
    vm_page_family_t *vm_page_family_curr; 
    uint32_t number_of_struct_families = 0;
    uint32_t total_memory_in_use_by_application = 0;
    uint32_t cumulative_vm_pages_claimed_from_kernel = 0;
    vm_page_for_families_t *vm_page_for_families_global;

    vm_page_for_families_global = mm_inst ?
        mm_inst->first_vm_page_for_families :
        first_vm_page_for_families;

    printf("\nPage Size = %zu Bytes\n", SYSTEM_PAGE_SIZE);

    ITERATE_PAGE_FAMILIES_BEGIN(vm_page_for_families_global, vm_page_family_curr){

        if(struct_name){
            if(strncmp(struct_name, vm_page_family_curr->struct_name, 
                strlen(vm_page_family_curr->struct_name))){
                continue;
            }
        }

        number_of_struct_families++;

        printf(ANSI_COLOR_GREEN "vm_page_family : %s, struct size = %u\n" 
                ANSI_COLOR_RESET,
                vm_page_family_curr->struct_name,
                vm_page_family_curr->struct_size);
        printf(ANSI_COLOR_CYAN "\tApp Used Memory %uB, #Sys Calls %u\n"
                ANSI_COLOR_RESET,
                vm_page_family_curr->total_memory_in_use_by_app,
                vm_page_family_curr->\
                no_of_system_calls_to_alloc_dealloc_vm_pages);
        
        total_memory_in_use_by_application += 
            vm_page_family_curr->total_memory_in_use_by_app;

        i = 0;

        ITERATE_VM_PAGE_BEGIN(vm_page_family_curr, vm_page){
      
            cumulative_vm_pages_claimed_from_kernel++;
            mm_print_vm_page_details(vm_page, i++);

        } ITERATE_VM_PAGE_END(vm_page_family_curr, vm_page);
        printf("\n");
    } ITERATE_PAGE_FAMILIES_END(vm_page_for_families_global, vm_page_family_curr);

    printf(ANSI_COLOR_MAGENTA "\nTotal Applcation Memory Usage : %u Bytes\n"
        ANSI_COLOR_RESET, total_memory_in_use_by_application);

    printf(ANSI_COLOR_MAGENTA "# Of VM Pages in Use : %u (%lu Bytes)\n" \
        ANSI_COLOR_RESET,
        cumulative_vm_pages_claimed_from_kernel, 
        SYSTEM_PAGE_SIZE * cumulative_vm_pages_claimed_from_kernel);

    float memory_app_use_to_total_memory_ratio = 0.0;
    
    if(cumulative_vm_pages_claimed_from_kernel){
        memory_app_use_to_total_memory_ratio = 
        (float)(total_memory_in_use_by_application * 100)/\
        (float)(cumulative_vm_pages_claimed_from_kernel * SYSTEM_PAGE_SIZE);
    }
    printf(ANSI_COLOR_MAGENTA "Memory In Use by Application = %f%%\n"
        ANSI_COLOR_RESET,
        memory_app_use_to_total_memory_ratio);

    printf("Total Memory being used by Memory Manager = %lu Bytes\n",
        cumulative_vm_pages_claimed_from_kernel * SYSTEM_PAGE_SIZE); 
}

void
mm_print_block_usage(mm_instance_t *mm_inst){

    vm_page_t *vm_page_curr;
    vm_page_family_t *vm_page_family_curr;
    block_meta_data_t *block_meta_data_curr;
    uint32_t total_block_count, free_block_count,
             occupied_block_count;
    uint32_t application_memory_usage;

    vm_page_for_families_t *first_vm_page_for_families_global;

    first_vm_page_for_families_global = mm_inst ?
        mm_inst->first_vm_page_for_families : first_vm_page_for_families;

    if (!first_vm_page_for_families_global) return;

    ITERATE_PAGE_FAMILIES_BEGIN(first_vm_page_for_families_global, vm_page_family_curr){

        total_block_count = 0;
        free_block_count = 0;
        application_memory_usage = 0;
        occupied_block_count = 0;
        ITERATE_VM_PAGE_BEGIN(vm_page_family_curr, vm_page_curr){

            ITERATE_VM_PAGE_ALL_BLOCKS_BEGIN(vm_page_curr, block_meta_data_curr){
        
                total_block_count++;
                
                /*Sanity Checks*/
                if(block_meta_data_curr->is_free == MM_FALSE){
                    assert(IS_GLTHREAD_LIST_EMPTY(&block_meta_data_curr->\
                        priority_thread_glue));
                }
                if(block_meta_data_curr->is_free == MM_TRUE){
                    assert(!IS_GLTHREAD_LIST_EMPTY(&block_meta_data_curr->\
                        priority_thread_glue));
                }

                if(block_meta_data_curr->is_free == MM_TRUE){
                    free_block_count++;
                }
                else{
                    application_memory_usage += 
                        block_meta_data_curr->block_size + \
                        sizeof(block_meta_data_t);
                    occupied_block_count++;
                }
            } ITERATE_VM_PAGE_ALL_BLOCKS_END(vm_page_curr, block_meta_data_curr);
        } ITERATE_VM_PAGE_END(vm_page_family_curr, vm_page_curr);

    printf("%-20s   TBC : %-4u    FBC : %-4u    OBC : %-4u AppMemUsage : %u\n",
        vm_page_family_curr->struct_name, total_block_count,
        free_block_count, occupied_block_count, application_memory_usage);

    } ITERATE_PAGE_FAMILIES_END(first_vm_page_for_families_global, vm_page_family_curr); 
}

void
mm_print_variable_buffers(mm_instance_t *mm_inst) {

    uint32_t total_block_count = 0;
    uint32_t  free_block_count = 0;
    uint32_t  application_memory_usage = 0;
    uint32_t occupied_block_count = 0;

    vm_page_t *vm_page_curr;
    vm_page_family_t *vm_page_family_curr;
    block_meta_data_t *block_meta_data_curr;
    vm_page_family_t *misc_vm_page_family_global;

    misc_vm_page_family_global = mm_inst ?
        &mm_inst->misc_vm_page_family : &misc_vm_page_family;

    ITERATE_VM_PAGE_BEGIN(misc_vm_page_family_global, vm_page_curr){

            ITERATE_VM_PAGE_ALL_BLOCKS_BEGIN(vm_page_curr, block_meta_data_curr){
        
                total_block_count++;
                
                /*Sanity Checks*/
                if(block_meta_data_curr->is_free == MM_FALSE){
                    assert(IS_GLTHREAD_LIST_EMPTY(&block_meta_data_curr->\
                        priority_thread_glue));
                }
                if(block_meta_data_curr->is_free == MM_TRUE){
                    assert(!IS_GLTHREAD_LIST_EMPTY(&block_meta_data_curr->\
                        priority_thread_glue));
                }

                if(block_meta_data_curr->is_free == MM_TRUE){
                    free_block_count++;
                }
                else{
                    application_memory_usage += 
                        block_meta_data_curr->block_size + \
                        sizeof(block_meta_data_t);
                    occupied_block_count++;
                }
            } ITERATE_VM_PAGE_ALL_BLOCKS_END(vm_page_curr, block_meta_data_curr);
        } ITERATE_VM_PAGE_END(misc_vm_page_family_global, vm_page_curr);

    printf("%-20s   TBC : %-4u    FBC : %-4u    OBC : %-4u AppMemUsage : %u\n",
        misc_vm_page_family.struct_name, total_block_count,
        free_block_count, occupied_block_count, application_memory_usage);

}

void
mm_print_registered_page_families(mm_instance_t *mm_inst){

    vm_page_family_t *vm_page_family_curr = NULL;
    vm_page_for_families_t *vm_page_for_families_curr = NULL;
    vm_page_for_families_t *vm_page_for_families_global;

    vm_page_for_families_global = mm_inst ?
        mm_inst->first_vm_page_for_families : first_vm_page_for_families;

    for(vm_page_for_families_curr = vm_page_for_families_global; 
        vm_page_for_families_curr; 
        vm_page_for_families_curr = vm_page_for_families_curr->next){

        ITERATE_PAGE_FAMILIES_BEGIN(vm_page_for_families_curr, 
            vm_page_family_curr){


            printf("Page Family : %s, Size = %u\n", 
                vm_page_family_curr->struct_name,
                vm_page_family_curr->struct_size);

        } ITERATE_PAGE_FAMILIES_END(vm_page_for_families_curr,
            vm_page_family_curr);
    }
}

void *
xcalloc_buff(mm_instance_t *mm_inst,  uint32_t bytes) {

    vm_page_family_t *misc_vm_page_family_global;

    misc_vm_page_family_global = mm_inst ?
        &mm_inst->misc_vm_page_family : &misc_vm_page_family;

    block_meta_data_t *free_block_meta_data = NULL;

    free_block_meta_data = mm_allocate_free_data_block(
                             misc_vm_page_family_global,  bytes);

     misc_vm_page_family_global->struct_size = bytes;

    if(free_block_meta_data){
        memset((char *)(free_block_meta_data + 1), 0, free_block_meta_data->block_size);
        return  (void *)(free_block_meta_data + 1);
    }

    return NULL;
}
