#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "mem_allocator/mem.h"
#include "disk_io/pager.h"
#include "mem_allocator/mem_allocator.h"

typedef struct stud_ {

    char name[32];
} stud_t;

extern void pg_mapped_addr_to_pg_no_ht_insert (void *mapped_addr, pg_no_t pg_no);
extern void  pg_pgno_to_mapped_addr_ht_insert (pg_no_t pg_no, void *mapped_addr) ;
extern void  mem_mgr_init () ;

#include <sys/mman.h>

int 
main (int argc, char **argv) {

    mem_mgr_init () ;

    /* Create a DB file on disk*/
    db_file_create_db_file ("sample1.db", 0);
       
    /* Open the DB file*/
    fd_t fd = db_file_open ("sample1.db");
    /* Allocate the DB page to use*/
    pg_no_t db_pg0 = db_file_alloc_db_page (fd);
    assert (db_pg0 != INVALID_DB_PG_NO);

    pg_no_t db_pg1 =  db_file_alloc_db_page (fd);
    /* mmap the DB page into process's VM*/
    void *db_pg1_ptr = db_file_mmap_db_page (fd, db_pg1);
    /* initialize the allocator to request memory for objects from
        DB page*/
    allocator_init (db_pg1_ptr, DB_PAGE_DEF_SIZE);
    pg_mapped_addr_to_pg_no_ht_insert (db_pg1_ptr, db_pg1);
    pg_pgno_to_mapped_addr_ht_insert (db_pg1, db_pg1_ptr);

    /* Lets allocate memort for student object and initialize it*/
    stud_t *stud1 = (stud_t *)allocator_alloc_mem ( sizeof(stud_t));
    strncpy (stud1->name, "Abhishek", sizeof(stud1->name));

    /* We re done, destory the mapping */
    db_page_memory_swipe_out  (db_pg1_ptr);

    /*close the DB file and exit the application */
    close (fd);

    fd = db_file_open ("sample1.db");

    void *ptr = mmap (NULL, DB_PAGE_DEF_SIZE *2 , PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    return 0;
}