#include <unistd.h>

#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <errno.h>
#include <cinttypes>
#include <memory.h>
#include "pager.h"
#include "../c-hashtable/hashtable.h"
#include "../c-hashtable/hashtable_itr.h"

#define HASH_PRIME_CONST    5381

static hashtable_t *pg_mapped_addr_to_pg_no_ht;
static hashtable_t *pg_pgno_to_mapped_addr_ht;

extern fd_t  db_file_open (const char* path);

static unsigned int
hashfromkey(void *key) {

    unsigned char *str = (unsigned char *)key;
    unsigned int hash = HASH_PRIME_CONST;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

static int
equalkeys(void *k1, void *k2) {

    void **key1 = (void **)k1;
    void **key2 = (void **)k2;
    return *key1 == *key2;
}

void  mem_mgr_init ()  {

    if (!pg_mapped_addr_to_pg_no_ht)
        pg_mapped_addr_to_pg_no_ht = create_hashtable(sizeof (uintptr_t), hashfromkey, equalkeys);

    if (!pg_pgno_to_mapped_addr_ht)
        pg_pgno_to_mapped_addr_ht = create_hashtable(sizeof (pg_no_t), hashfromkey, equalkeys);
}

void 
mem_mgr_destroy () {

    struct hashtable_itr *itr;

    if (hashtable_count(pg_mapped_addr_to_pg_no_ht)) {
        
        itr = hashtable_iterator(pg_mapped_addr_to_pg_no_ht);
        do
        {
            void **key = (void **)hashtable_iterator_key(itr);
            db_page_memory_swipe_out(*key);
        } while (hashtable_iterator_advance(itr));

        free(itr);
    }
    
    hashtable_destroy (pg_mapped_addr_to_pg_no_ht, false);
    hashtable_destroy (pg_pgno_to_mapped_addr_ht, false);
    pg_mapped_addr_to_pg_no_ht = NULL;
    pg_pgno_to_mapped_addr_ht = NULL;
}

void 
pg_mapped_addr_to_pg_no_ht_insert (void *mapped_addr, pg_no_t pg_no) {

    unsigned char *key = (unsigned char *) calloc (1, sizeof (uintptr_t));
    memcpy ( (char *)key,  (char *)&mapped_addr,  sizeof(uintptr_t));
    assert (hashtable_insert (pg_mapped_addr_to_pg_no_ht, (void *)key, (void *)pg_no));
}

void 
pg_pgno_to_mapped_addr_ht_insert (pg_no_t pg_no, void *mapped_addr) {

    unsigned char *key = (unsigned char *) calloc (1, sizeof (pg_no_t));
    memcpy ( (char *)key,  (char *)&pg_no,  sizeof(pg_no_t));
    assert (hashtable_insert (pg_pgno_to_mapped_addr_ht, (void *)key, (void *)mapped_addr));
}

pg_no_t 
ht_lookup_page_no_by_page_address (void *ptr) {

    return (pg_no_t)hashtable_search (pg_mapped_addr_to_pg_no_ht, &ptr);
}

void *
ht_lookup_page_addr_by_page_no (pg_no_t pg_no) {

    return (void *)hashtable_search (pg_pgno_to_mapped_addr_ht, &pg_no);
}



/* Offset to page no & Vice-versa conversion functions*/
pg_offset_t
db_page_get_offset (pg_no_t pg_no) {

    pg_offset_t offset = 0;
    offset +=  (pg_no  * DB_PAGE_DEF_SIZE);
    return offset;
}

static void 
db_file_init_hdr (fd_t fd) {

    int i;

    db_file_hdr_t *db_hdr = (db_file_hdr_t *)disk_io_file_mmap 
                                                    (fd, 0, sizeof (db_file_hdr_t));
                                                  
    for (i = 0 ; i < free_pg_bitmap_size; i++) {

        db_hdr->allocated_pg_bitmap[i] = 0;
    }
    
    /* Mark page 0 as allocated already */
   db_hdr->allocated_pg_bitmap[0] |= (1UL << 63);
   disk_file_unmap ( (void *)db_hdr, sizeof (db_file_hdr_t));
}

void
db_file_create_db_file (const char* path, uint64_t size) {

    fd_t fd;

    disk_io_create_disk_file (path, 
        (DB_FILE_DEF_PAGE_CNT *  DB_PAGE_DEF_SIZE));

    fd = disk_io_open_file (path);

    /* initialize the Hdr of the DB file*/
    db_file_init_hdr (fd);

    close (fd);
}

fd_t 
db_file_open (const char* path) {

    mem_mgr_init ();
    return disk_io_open_file (path);
}

void 
db_file_close (fd_t fd) {

    mem_mgr_destroy ();
    close (fd);
}

void 
db_file_delete (const char* path) {

    disk_io_delete_file (path);
}

pg_no_t
db_file_alloc_db_page (fd_t fd) {

    int i;
    uint64_t var;
    pg_no_t pos = 0;

    uint64_t msb = 1UL << 63;
    
    db_file_hdr_t *db_hdr = (db_file_hdr_t *)disk_io_file_mmap 
                                                            (fd, 0, sizeof (db_file_hdr_t));

    for (i = 0;  i < free_pg_bitmap_size; i++) {

        if (db_hdr->allocated_pg_bitmap[i] == UINT64_MAX) {

            pos += 64;
            continue;
        }

        var = db_hdr->allocated_pg_bitmap[i];

        /* Find the Ist zeroth bit */
        while (var & msb) {
            var = var << 1;
            pos++;
        }

        db_hdr->allocated_pg_bitmap[i] |= (1UL << (63 - (pos % 64) ));
        disk_file_unmap ( (void *)db_hdr, sizeof (db_file_hdr_t));
        return pos;
    }

    disk_file_unmap ( (void *)db_hdr, sizeof (db_file_hdr_t));
    return INVALID_DB_PG_NO;
}

bool 
db_file_free_db_page (fd_t fd, pg_no_t pg_no) {

    db_file_hdr_t *db_hdr = (db_file_hdr_t *)disk_io_file_mmap 
                                                            (fd, 0, sizeof (db_file_hdr_t));

    int block_no = pg_no / 64;
    int bit_no = 63 - (pg_no % 64);

    db_hdr->allocated_pg_bitmap[block_no] &= ~(1UL << bit_no);
    disk_file_unmap ( (void *)db_hdr, sizeof (db_file_hdr_t));
    return true;
}

void *
db_file_mmap_db_page (fd_t fd, pg_no_t pg_no) {

    pg_offset_t offset = db_page_get_offset (pg_no);
    void *ptr = disk_io_file_mmap (fd, offset, offset + DB_PAGE_DEF_SIZE );
    if (ptr == MAP_FAILED) {
        printf ("mmap failed with err : %d\n", errno);
        exit(0);
    }
    return ptr;
}

void 
db_file_munmap_db_page (void *addr) {

    disk_file_unmap (addr, DB_PAGE_DEF_SIZE);
}

pg_no_t
db_get_container_page_from_offset (uint64_t db_file_offset) {

    pg_no_t pg_no = (db_file_offset / DB_PAGE_DEF_SIZE ) ;
    return pg_no;
}

void 
db_file_print_stats (fd_t fd) {

    int i, j = 0;
    uint64_t var;
    pg_no_t pg_no = 0;
    
    uint64_t msb = 1UL << 63;

    db_file_hdr_t *db_hdr = (db_file_hdr_t *)disk_io_file_mmap 
                                                            (fd, 0, sizeof (db_file_hdr_t));

    for (i = 0 ; i < free_pg_bitmap_size; i++) {

        var = db_hdr->allocated_pg_bitmap[i];
        
        for (j = 0 ; j < 64; j++) {
            
            if (var & msb) {
                printf ("Page no %lu in use\n", pg_no);
            }
            var = var << 1;
            pg_no++;
        }
    }

    disk_file_unmap ( (void *)db_hdr, sizeof (db_file_hdr_t));
}

void allocator_reinit (void *base_address);
void allocator_deinit (void *base_address);

/* Swipe in the DB page again into main-memory, Dont use this API
    to swipe in the page for the first time*/
void 
db_page_memory_swipe_in (fd_t fd, pg_no_t pg_no) {

    /* This page should be allocated in DB file*/

    /* Load the page in Main-memory*/
    void *base_address = db_file_mmap_db_page (fd, pg_no);
    allocator_reinit (base_address);
    pg_mapped_addr_to_pg_no_ht_insert (base_address, pg_no);
    pg_pgno_to_mapped_addr_ht_insert (pg_no, base_address);
}

void 
db_page_memory_swipe_out (void *base_address) {

    pg_no_t pg_no;
    allocator_deinit (base_address);
    db_file_munmap_db_page(base_address);
    pg_no = (pg_no_t)hashtable_search(pg_mapped_addr_to_pg_no_ht, &base_address);
    hashtable_remove(pg_mapped_addr_to_pg_no_ht, &base_address);
    hashtable_remove(pg_pgno_to_mapped_addr_ht, &pg_no);
}