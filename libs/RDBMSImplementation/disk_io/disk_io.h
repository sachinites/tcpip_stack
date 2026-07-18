#ifndef __DISK_IO__
#define __DISK_IO__

#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define DB_PAGE_DEF_SIZE    getpagesize()

typedef int fd_t;
typedef uint64_t fsize;
typedef uint64_t file_addr_t;

/* API to create a disk file*/
void
disk_io_create_disk_file (const char* path, fsize size);

void
disk_io_delete_file (const char* path);

void 
disk_io_write_to_file (fd_t fd, int offset, char *data, int data_size);

void
disk_io_truncate_file_size (fd_t fd, int tr_size);

void
disk_io_expand_file_size (fd_t fd, int ex_size);

fd_t 
disk_io_open_file (const char* path);

void *
disk_io_file_mmap (fd_t fd, uint64_t start_offset, uint64_t end_offset);

void
disk_file_unmap (void *pptr, uint64_t len);

#endif 