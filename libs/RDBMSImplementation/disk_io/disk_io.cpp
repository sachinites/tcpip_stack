#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <assert.h>
#include "disk_io.h"

void
disk_io_create_disk_file (const char* path, fsize size) {

    fd_t fd;
    FILE *file;

    if (access(path, F_OK) == -1) {
        /* File do not exist or we dont have permissions, 
            then create the file*/
        file = fopen(path, "w+");
    }
    else {
        file = fopen(path, "r+");
    }

    if (!file) assert(0);

    fd = fileno (file);

#if 1
    if (ftruncate(fd, size) == -1) {
        assert(0); 
    }
#else 
    disk_io_expand_file_size (fd, size);
#endif 

    assert (fsync(fd) != -1);
    fclose (file);
}

fd_t 
disk_io_open_file (const char* path) {

    FILE *file = fopen (path, "r+");

    if (!file) assert(0);

    fd_t fd = fileno (file);

    return fd;
}

void
disk_io_delete_file (const char* path) {

    assert (unlink(path) == 0);
}

void
disk_io_write_to_file (fd_t fd, int offset, char *data, int data_size) {

    if (offset >= 0 && 
        lseek(fd,  offset, SEEK_SET) == -1) {
        assert(0);
    }

    assert (write (fd, data, data_size) != -1 );
}

void
disk_io_truncate_file_size (fd_t fd, int tr_size) {

    if (ftruncate(fd, tr_size) == -1) {
        assert(0);
    }
}

void
disk_io_expand_file_size (fd_t fd, int ex_size) {

    if (lseek(fd, ex_size - 1, SEEK_SET) == -1) {
        assert(0);
    }
}

void *
disk_io_file_mmap (fd_t fd, uint64_t start_offset, uint64_t end_offset) {

    assert (start_offset % DB_PAGE_DEF_SIZE == 0);

    void *pptr = mmap (NULL, end_offset - start_offset, 
                                        PROT_READ | PROT_WRITE, MAP_SHARED, 
                                        fd, start_offset);
    return pptr;
}

void
disk_file_unmap (void *pptr, uint64_t len) {

    munmap (pptr, len);
}

#if 0

#include <errno.h>


int 
main (int argc, char **argv) {

    fd_t fd;
    FILE *file;
    
    const char *file_name = "db-sample.txt";

    if (access(file_name, F_OK) == -1) {
        /* File do not exist or we dont have permissions, 
            then create the file*/
        file = fopen(file_name, "w+");
    }
    else {
        file = fopen(file_name, "r+");
    }

    if (!file) assert(0);

    fd = fileno (file);

    if (ftruncate(fd, 8192 * 64) == -1) {
        assert(0);
    }

    disk_io_write_to_file (fd, 0, "Hello World", strlen ("Hello World"));

    lseek(fd,  0, SEEK_SET);

    assert (write (fd, "Hello World",  strlen("Hello World") - 1) != -1 );

#if 0
    void *ptr1 = mmap (NULL, 8, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (ptr1 == MAP_FAILED) {
        printf ("%d : Error : mmap failed with error %d\n", __LINE__, errno);
        exit(0);
    }
#endif
    void *ptr2 = mmap (NULL,  8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (ptr2 == MAP_FAILED) {
        printf ("%d : Error : mmap failed with error %d\n", __LINE__, errno);
        exit(0);
    }

    munmap (ptr1, 8);
    munmap (ptr2, 8192);

    return 0;
}

#endif