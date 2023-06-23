#ifndef __TRACER_T__
#define __TRACER_T__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

typedef struct tracer_ tracer_t;

tracer_t *
tracer_init (const char *tr_str_id, const char *file_name, const char *hdr, int out_fd, uint64_t logging_bits);

void
tracer_deinit (tracer_t *tracer) ;

#define trace(tr_ptr, bitn, ...) \
    trace_internal(tr_ptr, bitn, __FUNCTION__, __LINE__, __VA_ARGS__);
    
void 
trace_internal (tracer_t *tracer, uint64_t bit, const char *FN, const int lineno, const char *format, ...);

void 
tracer_enable_file_logging (tracer_t *tracer, bool enable);

void 
tracer_enable_console_logging (tracer_t *tracer, bool enable);

bool 
tracer_is_console_logging_enable (tracer_t *tracer);

bool 
tracer_is_file_logging_enable (tracer_t *tracer);

void 
tracer_log_bit_set (tracer_t *tracer, uint64_t log_bit);

void 
tracer_log_bit_unset (tracer_t *tracer, uint64_t log_bit);

bool 
tracer_is_bit_set (tracer_t *tracer, uint64_t log_bit);

void 
tracer_clear_log_file (tracer_t *tracer);

void 
tracer_disable_hdr_print (tracer_t *tracer);

#endif 