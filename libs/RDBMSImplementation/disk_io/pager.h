#ifndef __DISK_FILE_MGMT__
#define __DISK_FILE_MGMT__

#define DB_FILE_DEF_PAGE_CNT    64

#include "disk_io.h"

typedef uint64_t pg_offset_t;
typedef uint64_t pg_no_t;

#define INVALID_DB_PG_NO    UINT64_MAX

#define free_pg_bitmap_size \
    (DB_FILE_DEF_PAGE_CNT / 64)

#pragma pack (push,1)

typedef struct db_file_hdr_ {

    /* Most Significant bit is 0*/
    uint64_t allocated_pg_bitmap[free_pg_bitmap_size];

} db_file_hdr_t;

#pragma pack(pop)


pg_no_t
db_file_alloc_db_page (fd_t fd);

bool 
db_file_free_db_page (fd_t fd, pg_no_t pg_no);

void *
db_file_mmap_db_page (fd_t fd, pg_no_t pg_no);

void 
db_file_munmap_db_page (void *addr);

void 
db_file_print_stats (fd_t fd);

pg_offset_t
db_page_get_offset (pg_no_t pg_no) ;

pg_no_t
db_get_container_page_from_offset (uint64_t db_file_offset);

void 
db_page_memory_swipe_in (fd_t fd, pg_no_t pg_no);

void 
db_page_memory_swipe_out (void *base_address);

void 
pg_mapped_addr_to_pg_no_ht_insert (void *mapped_addr, pg_no_t pg_no);

void 
pg_pgno_to_mapped_addr_ht_insert (pg_no_t pg_no, void *mapped_addr) ;

pg_no_t  ht_lookup_page_no_by_page_address (void *ptr);
void * ht_lookup_page_addr_by_page_no (pg_no_t pg_no);

void  mem_mgr_init ()  ;
void mem_mgr_destroy () ;

#endif 