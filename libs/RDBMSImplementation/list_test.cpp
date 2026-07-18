#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mem_allocator/mem.h"

typedef struct stud_ {

    char name [32];
    uint64_t left;
    uint64_t right;
} stud_t;

/* Creator main*/
int 
main (int argc, char **argv) {

    stud_t *vm_addr1;
    uint64_t disk_addr1;

    db_file_create_db_file ("list.db", 0);

    fd_t fd = db_file_open ("list.db");

    disk_addr1 = uapi_mem_alloc (fd, sizeof(stud_t),  (void **)&vm_addr1);

    strncpy ((char *)vm_addr1, "Abhishek", strlen ("Abhishek"));
    vm_addr1->left = 0;
    vm_addr1->right = 0;

    stud_t *vm_addr2;
    uint64_t disk_addr2;

    disk_addr2 = uapi_mem_alloc (fd, sizeof(stud_t),  (void **)&vm_addr2);

    strncpy ((char *)vm_addr2, "Madhvi", strlen ("Madhvi"));
    vm_addr2->left = 0;
    vm_addr2->right = 0;

    vm_addr1->right = disk_addr2;
    vm_addr2->left = disk_addr1;

    stud_t *vm_addr3;
    uint64_t disk_addr3;
    disk_addr3 = uapi_mem_alloc (fd, sizeof(stud_t),  (void **)&vm_addr3);


    uapi_mem_free(fd, disk_addr1);
    uapi_mem_free(fd, disk_addr2);
    uapi_mem_free(fd, disk_addr3);

    db_file_close (fd);
    return 0;
}


