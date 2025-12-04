#include <stdlib.h>
#include <assert.h>
#include <cstdarg>
#include <memory.h>
#include <unistd.h>
#include <pthread.h>
#include <ncurses.h>
#include <sys/time.h>
#include <time.h>
#include <assert.h>
#include "tracer.h"


#define HDR_SIZE    64
#define LOG_BUFFER_SIZE 256

#define CLI_INTG

#ifdef CLI_INTG
extern int cprintf (const char* format, ...) ;
#endif 

/* Reserved bits, Application is not allowed to use these bits*/
#define ENABLE_FILE_LOG (1ULL << 63)
#define ENABLE_CONSOLE_LOG (1ULL << 62)
#define DISABLE_HDR_PRINTING (1ULL << 61)
#define DENABLE_ALWAYS_FLUSH (1ULL << 60)
#define DENABLE_ALL_LOGGING (1ULL << 59)

typedef struct tracer_ {

    unsigned char tr_name[12];
    unsigned char Logbuffer[LOG_BUFFER_SIZE];
    int log_msg_len;
    int hdr_size;
    FILE *log_file;
    int out_fd;
    uint64_t bits;
    struct tracer_ *left;
    struct tracer_ *right;
    uint64_t op_flags;
    int (*bit_to_str)(char *, uint64_t );
    pthread_spinlock_t spin_lock;
} tracer_t;

tracer_t *
tracer_init (const char *tr_str_id, 
                  const char *file_name, 
                  const char *hdr, int out_fd,
                  int (*bit_to_str)(char *, uint64_t) ){

    assert (tr_str_id);

    tracer_t *tr = (tracer_t *)calloc(1, sizeof (tracer_t));
    
    strncpy ((char *)tr->tr_name, tr_str_id, sizeof (tr->tr_name));

    if (file_name) {
        tr->log_file = fopen (file_name, "w+");
        assert (tr->log_file);
    }

    if (hdr) {
        tr->hdr_size = snprintf ((char *)tr->Logbuffer, HDR_SIZE, "%s : ", hdr);
    }
    tr->log_msg_len = tr->hdr_size;
    tr->out_fd = out_fd;
    tr->bit_to_str = bit_to_str;
    pthread_spin_init (&tr->spin_lock, PTHREAD_PROCESS_PRIVATE);
    return tr;
}

void
tracer_deinit (tracer_t *tracer) {

    if (tracer->log_file) {
        fclose (tracer->log_file);
        tracer->log_file = NULL;
    }

    pthread_spin_destroy (&tracer->spin_lock);
    free (tracer);
}

static int
time_get_current (char *buffer) {

    struct timeval current_time;
    struct tm *local_time;

    // Get the current time
    gettimeofday(&current_time, NULL);

    // Convert to local time format
    local_time = localtime(&current_time.tv_sec);

    // Print the current time with microseconds precision
    return snprintf(buffer, 32, "%02d-%02d-%04d %02d:%02d:%02d.%06ld",
           local_time->tm_mday,
           local_time->tm_mon + 1,  // tm_mon is months since January (0-11)
           local_time->tm_year + 1900,  // tm_year is years since 1900
           local_time->tm_hour,
           local_time->tm_min,
           local_time->tm_sec,
           current_time.tv_usec);
}

void 
trace_internal (tracer_t *tracer,
          uint64_t bit,
          const char *FN,
          const int lineno,
          const char *format, ...) {

    va_list args;

    pthread_spin_lock (&tracer->spin_lock);

    if (!(tracer->bits & bit) && !(tracer->bits & DENABLE_ALL_LOGGING)) {
        pthread_spin_unlock (&tracer->spin_lock);
        return;
    }

    if (!tracer->op_flags) {
        pthread_spin_unlock (&tracer->spin_lock);
        return;
    }

    va_start(args, format);
    memset (tracer->Logbuffer + tracer->hdr_size, 0, tracer->log_msg_len - tracer->hdr_size);
    tracer->log_msg_len = tracer->hdr_size;
    tracer->log_msg_len += time_get_current ((char *)tracer->Logbuffer + tracer->log_msg_len);
    tracer->log_msg_len += sprintf ((char *)tracer->Logbuffer + tracer->log_msg_len , " %s(%d): ", FN, lineno);
    if (tracer->bit_to_str) {
        tracer->log_msg_len += tracer->bit_to_str((char *)tracer->Logbuffer + tracer->log_msg_len, bit);
    }
    tracer->log_msg_len += vsnprintf((char *)tracer->Logbuffer + tracer->log_msg_len, LOG_BUFFER_SIZE - tracer->log_msg_len, format, args);
    // Don't include the null terminator in the log output
    va_end(args);

    if (tracer->log_file && (tracer->op_flags & ENABLE_FILE_LOG)) {
        
        if (tracer->op_flags & DISABLE_HDR_PRINTING) {
            fwrite (tracer->Logbuffer + HDR_SIZE, 1 , tracer->log_msg_len - HDR_SIZE, tracer->log_file);
        }
        else {
             fwrite (tracer->Logbuffer, 1 , tracer->log_msg_len, tracer->log_file);
        }

        if ((tracer->bits & DENABLE_ALWAYS_FLUSH)) {
            fflush (tracer->log_file);
        }
    }

    if (tracer->op_flags & ENABLE_CONSOLE_LOG) {
        #ifndef CLI_INTG
        if (tracer->op_flags & DISABLE_HDR_PRINTING) {
            write (tracer->out_fd, tracer->Logbuffer + HDR_SIZE, tracer->log_msg_len - HDR_SIZE);
        }
        else {
            write (tracer->out_fd, tracer->Logbuffer, tracer->log_msg_len);
        }
        #else 
        if (tracer->op_flags & DISABLE_HDR_PRINTING) {
            cprintf ("%s", tracer->Logbuffer + HDR_SIZE, tracer->log_msg_len - HDR_SIZE);
        }
        else {
            cprintf ("%s",  tracer->Logbuffer);
        }
        refresh();
        #endif
    }

    tracer->op_flags &= ~DISABLE_HDR_PRINTING;
    pthread_spin_unlock (&tracer->spin_lock);
 }

void 
tracer_enable_file_logging (tracer_t *tracer, bool enable) {

    pthread_spin_lock (&tracer->spin_lock);

    if (enable) {
        tracer->op_flags |= ENABLE_FILE_LOG;
    }
    else {
        tracer->op_flags &= ~ENABLE_FILE_LOG;
    }

    pthread_spin_unlock (&tracer->spin_lock);
}

bool 
tracer_is_active (tracer_t *tracer, uint64_t log_bit) {

    bool rc = false;
    pthread_spin_lock (&tracer->spin_lock);
    rc = tracer->op_flags & ENABLE_CONSOLE_LOG ? true : false;
    rc |= tracer->op_flags & ENABLE_FILE_LOG ? true : false;
    if (!rc) {
        pthread_spin_unlock (&tracer->spin_lock);
        return false;
    }
    rc = (tracer->bits & log_bit) ? true : false;
    rc |= (tracer->bits & DENABLE_ALL_LOGGING) ? true : false;
    pthread_spin_unlock (&tracer->spin_lock);
    return rc;
}

void 
tracer_disable_hdr_print (tracer_t *tracer) {

    pthread_spin_lock (&tracer->spin_lock);
     tracer->op_flags |= DISABLE_HDR_PRINTING;
    pthread_spin_unlock (&tracer->spin_lock);
}

void 
tracer_enable_console_logging (tracer_t *tracer, bool enable) {

    pthread_spin_lock (&tracer->spin_lock);

    if (enable) {
        tracer->op_flags |= ENABLE_CONSOLE_LOG;
    }
    else {
        tracer->op_flags &= ~ENABLE_CONSOLE_LOG;
    }

    pthread_spin_unlock (&tracer->spin_lock);
}

void 
tracer_log_bit_set (tracer_t *tracer, uint64_t log_bit) {

    pthread_spin_lock (&tracer->spin_lock);
    tracer->bits |= log_bit;
    pthread_spin_unlock (&tracer->spin_lock);
}

void 
tracer_log_bit_unset (tracer_t *tracer, uint64_t log_bit){

    pthread_spin_lock (&tracer->spin_lock);
    tracer->bits &= ~log_bit;
    pthread_spin_unlock (&tracer->spin_lock);
}

void 
tracer_clear_log_file (tracer_t *tracer) {

    pthread_spin_lock (&tracer->spin_lock);
    if (tracer->log_file) {
        tracer->log_file = freopen (NULL, "w+", tracer->log_file);
    }
    pthread_spin_unlock (&tracer->spin_lock);
}

bool 
tracer_is_bit_set (tracer_t *tracer, uint64_t log_bit) {

    bool rc;
    pthread_spin_lock (&tracer->spin_lock);
    rc = tracer->bits & log_bit;
    pthread_spin_unlock (&tracer->spin_lock);
    return rc;
}

bool 
tracer_is_console_logging_enable (tracer_t *tracer) {

    bool rc;
    pthread_spin_lock (&tracer->spin_lock);
    rc = tracer->op_flags & ENABLE_CONSOLE_LOG;
    pthread_spin_unlock (&tracer->spin_lock);
    return rc;    
}

bool 
tracer_is_file_logging_enable (tracer_t *tracer) {

    bool rc;
    pthread_spin_lock (&tracer->spin_lock);
    rc = tracer->op_flags & ENABLE_FILE_LOG;
    pthread_spin_unlock (&tracer->spin_lock);
    return rc;        
}

void 
tracer_enable_always_flush (tracer_t *tracer, bool always_flush) {

    pthread_spin_lock (&tracer->spin_lock);

    if (always_flush)
       tracer->bits |=  DENABLE_ALWAYS_FLUSH;
    else 
        tracer->bits &= ~DENABLE_ALWAYS_FLUSH;

    pthread_spin_unlock (&tracer->spin_lock);        
}

bool 
tracer_is_all_logging_enable (tracer_t *tracer) {

    return tracer_is_bit_set (tracer, DENABLE_ALL_LOGGING);
}

bool
tracer_get_always_flush_status (tracer_t *tracer) {

    return tracer_is_bit_set (tracer, DENABLE_ALWAYS_FLUSH);
}

void 
tracer_flush (tracer_t *tracer) {

    pthread_spin_lock (&tracer->spin_lock);
    if (tracer->log_file) {
        fflush (tracer->log_file);
    }
    pthread_spin_unlock (&tracer->spin_lock);
}

void 
tracer_enable_all_logging (tracer_t *tracer, bool enable) {

    pthread_spin_lock (&tracer->spin_lock);

    if (enable)
       tracer->bits |=  DENABLE_ALL_LOGGING;
    else 
        tracer->bits &= ~DENABLE_ALL_LOGGING;

    pthread_spin_unlock (&tracer->spin_lock);            
}

bool 
tracer_is_reserved_bit (uint64_t bit) {

    return ((bit & ENABLE_FILE_LOG) || 
                (bit & ENABLE_CONSOLE_LOG) || 
                (bit & DISABLE_HDR_PRINTING) || 
                (bit & DENABLE_ALWAYS_FLUSH) || 
                (bit & DENABLE_ALL_LOGGING));
}