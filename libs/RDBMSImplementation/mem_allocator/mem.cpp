#include <assert.h>
#include <string.h>
#include <memory.h>
#include <stdlib.h>
#include "mem.h"
#include "mem_allocator.h"
#include "../disk_io/pager.h"
#include "../gluethread/glthread.h"
#include "../c-hashtable/hashtable.h"
#include "../c-hashtable/hashtable_itr.h"

extern glthread_t free_block_list_head;

uint64_t
uapi_mem_alloc (fd_t fd, uint32_t req_size, void **ptr) {

    glthread_t *curr;
    block_meta_data_t *block_meta_data;

    curr = glthread_get_next (&free_block_list_head);
    
    if (!curr) {
        /* Reserve a new DB page in DB file on disk*/
        pg_no_t db_pg = db_file_alloc_db_page (fd);
        assert (db_pg != INVALID_DB_PG_NO);

        /* mmap the DB page into process's VM*/
        void *db_pg_ptr = db_file_mmap_db_page (fd, db_pg);

        /* Update Hashtables*/
        pg_mapped_addr_to_pg_no_ht_insert (db_pg_ptr, db_pg);
        pg_pgno_to_mapped_addr_ht_insert (db_pg, db_pg_ptr);

        /* intialize the DB page loaded in memory for memory allocation
            by the application*/
        allocator_init (db_pg_ptr, DB_PAGE_DEF_SIZE);

        curr = glthread_get_next (&free_block_list_head);
    }

    if (!curr) {

        /* Even a new DB page could not satisfy request, appln request cannot be 
            satisfied, consider increase the size of macro DB_PAGE_DEF_SIZE to higher value*/
            assert (0);
    }

    block_meta_data = pq_glue_to_block_meta_data (curr);

    *ptr = allocator_alloc_mem (req_size);
    assert(*ptr);

    pg_no_t pg_no = ht_lookup_page_no_by_page_address ((void *)block_meta_data->base_address);

    pg_offset_t pg_offset = db_page_get_offset (pg_no);

    return pg_offset + (uint64_t) ((char *) *ptr - (char *)block_meta_data->base_address);
}

uint32_t 
uapi_mem_free (fd_t fd, uint64_t disk_addr) {

    uint32_t mem_freed;

    pg_no_t pg_no = db_get_container_page_from_offset (disk_addr);

    assert (pg_no != INVALID_DB_PG_NO);

    pg_offset_t pg_offset =  db_page_get_offset (pg_no);

    uint64_t offset_within_page = disk_addr - pg_offset;
 
    /*Check of the disk page is mapped in main memory*/
    void *page_mapped_addr = ht_lookup_page_addr_by_page_no (pg_no);

    if (!page_mapped_addr) {
        /* DB Page is not present in memory, load it*/
        page_mapped_addr = db_file_mmap_db_page (fd, pg_no);
    }

    /* Disk page is loaded in memory, release the object from main memory loaded page*/
    void *object_addr = (void *)((char *)page_mapped_addr + offset_within_page);

    mem_freed = allocator_free_mem(object_addr);

    if (allocator_is_vm_page_empty(page_mapped_addr)) {

        db_page_memory_swipe_out(page_mapped_addr);
        db_file_free_db_page(fd, pg_no);
    }

    return mem_freed;
}

void *
uapi_get_vm_addr (fd_t fd, uint64_t disk_addr) {

    if (disk_addr == 0) return NULL;
    
    pg_no_t pg_no = db_get_container_page_from_offset (disk_addr);

    assert (pg_no != INVALID_DB_PG_NO);

    pg_offset_t pg_offset =  db_page_get_offset (pg_no);

    uint64_t offset_within_page = disk_addr - pg_offset;
 
    /*Check of the disk page is mapped in main memory*/
    void *page_mapped_addr = ht_lookup_page_addr_by_page_no (pg_no);

    if (!page_mapped_addr) {
        /* DB Page is not present in memory, load it*/
        db_page_memory_swipe_in(fd, pg_no);
    }

    /* Disk page is loaded in memory, release the object from main memory loaded page*/
    void *object_addr = (void *)((char *)page_mapped_addr + offset_within_page);

    return object_addr;
}
