#include <assert.h>
#include <stdlib.h>
#include "../LinuxMemoryManager/uapi_mm.h"
#include "refcount.h"

struct ref_count_ {

    uint32_t ref_count;
    pthread_spinlock_t spinlock;
};

void
ref_count_init (ref_count_t *ref_count) {

    *ref_count = (ref_count_t )XCALLOC(0, 1, struct ref_count_);
    (*ref_count)->ref_count = 0;
    pthread_spin_init(&(*ref_count)->spinlock, PTHREAD_PROCESS_PRIVATE);
}

void
ref_count_destroy (ref_count_t ref_count) {

    assert(ref_count_get_value(ref_count) == 0);
    pthread_spin_destroy(&ref_count->spinlock);
    XFREE(ref_count);
}

void
ref_count_inc (ref_count_t ref_count) {

   // pthread_spin_lock(&ref_count->spinlock);
    ref_count->ref_count++;
    //pthread_spin_unlock(&ref_count->spinlock);
}

bool
ref_count_dec (ref_count_t ref_count) {

    bool rc;
    pthread_spin_lock(&ref_count->spinlock);
    assert(ref_count->ref_count);
    ref_count->ref_count--;
    rc = (ref_count->ref_count == 0);
    pthread_spin_unlock(&ref_count->spinlock);
    return rc;
}

uint32_t 
ref_count_get_value (ref_count_t ref_count) {

    uint32_t val;
    pthread_spin_lock(&ref_count->spinlock);
    val = ref_count->ref_count;
    pthread_spin_unlock(&ref_count->spinlock);
    return val;
}

void
thread_using_object (ref_count_t ref_count) {

    ref_count_inc(ref_count);
}

bool
thread_using_object_done (ref_count_t ref_count) {

  return  ref_count_dec (ref_count);
}

void
ref_count_mem_init () {

    MM_REG_STRUCT(0, struct ref_count_);
}