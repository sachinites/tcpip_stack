#ifndef __MEM_H__
#define __MEM_H__

#include <stdint.h>
#include "mem_allocator.h"
#include "../disk_io/disk_io.h"

void 
db_file_create_db_file (const char* path,  uint64_t size);

fd_t 
db_file_open (const char* path);

uint64_t
uapi_mem_alloc (fd_t fd, uint32_t req_size, void **ptr);

uint32_t
uapi_mem_free (fd_t fd, uint64_t disk_addr) ;

void *
uapi_get_vm_addr (fd_t fd, uint64_t disk_addr);

void
db_file_close (fd_t fd);

void 
db_file_delete (const char* path);

#endif 