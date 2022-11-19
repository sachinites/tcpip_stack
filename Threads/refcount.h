#ifndef __REF_COUNT__
#define __REF_COUNT__

#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct ref_count_  * ref_count_t;

void
ref_count_init (ref_count_t *ref_count);

void
ref_count_inc (ref_count_t ref_count);

/* Returns true if the value if ref_count  after dec is zero*/
bool
ref_count_dec (ref_count_t ref_count);

void
ref_count_destroy (ref_count_t ref_count);

uint32_t 
ref_count_get_value (ref_count_t ref_count);

void
thread_using_object (ref_count_t ref_count);

/* Returns True if the object should be deleted by the application */
bool
thread_using_object_done (ref_count_t ref_count);

#endif 