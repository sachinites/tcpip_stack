#include <stdlib.h>
#include <assert.h>
#include <cstdarg>
#include <memory.h>
#include <unistd.h>
#include <pthread.h>
#include <ncurses.h>
#include "tracer.h"


#define HDR_SIZE    32
#define LOG_BUFFER_SIZE 256

#define CLI_INTG

#ifdef CLI_INTG
extern int cprintf (const char* format, ...) ;
#endif 

static uint64_t flush_count = 0;
#define FLUSH_MAX   10

typedef enum log_flags_ {

    ENABLE_FILE_LOG = 1,
    ENABLE_CONSOLE_LOG = 2,
    DISABLE_HDR_PRINTING = 4
}log_flags_t;

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
    uint8_t op_flags;
    pthread_spinlock_t spin_lock;
} tracer_t;

static tracer_t *list_head = NULL;

static void 
tracer_save (tracer_t *tracer) {

    if (!list_head) list_head = tracer;
    tracer->right = list_head;
    list_head->left = tracer;
    list_head = tracer;
}

tracer_t *
tracer_init (const char *tr_str_id, const char *file_name, const char *hdr, int out_fd, uint64_t logging_bits) {

    assert (tr_str_id);

    tracer_t *tr = (tracer_t *)calloc(1, sizeof (tracer_t));
    
    if (file_name) {
        tr->log_file = fopen (file_name, "w+");
        assert (tr->log_file);
    }

    if (hdr) {
        tr->hdr_size = snprintf ((char *)tr->Logbuffer, HDR_SIZE, "%s : ", hdr);
    }
    tr->log_msg_len = tr->hdr_size;
    tr->out_fd = out_fd;
    tr->bits = logging_bits;
    pthread_spin_init (&tr->spin_lock, PTHREAD_PROCESS_PRIVATE);
    tracer_save (tr);
    return tr;
}

static void
tracer_remove(tracer_t *tracer){
    
    if(!tracer->left){
        if(tracer->right){
            tracer->right->left = NULL;
            tracer->right = 0;
            return;
        }   
        return;
    }   
    if(!tracer->right){
        tracer->left->right = NULL;
        tracer->left = NULL;
        return;
    }   

    tracer->left->right = tracer->right;
    tracer->right->left = tracer->left;
    tracer->left = 0;
    tracer->right = 0;
}

void
tracer_deinit (tracer_t *tracer) {

    if (tracer->log_file) {
        fclose (tracer->log_file);
        tracer->log_file = NULL;
    }

    pthread_spin_destroy (&tracer->spin_lock);

    if (list_head == tracer) {
        list_head = tracer->right;
        if (list_head) list_head->left = NULL;
        free(tracer);
        return;
    }

    tracer_remove (tracer);
    free (tracer);
}

void 
trace_internal (tracer_t *tracer,
          uint64_t bit,
          const char *FN,
          const int lineno,
          const char *format, ...) {

    va_list args;

    pthread_spin_lock (&tracer->spin_lock);

    if (!(tracer->bits & bit)) {
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
    tracer->log_msg_len += sprintf ((char *)tracer->Logbuffer + tracer->log_msg_len , "%s(%d): ", FN, lineno);
    tracer->log_msg_len += vsnprintf((char *)tracer->Logbuffer + tracer->log_msg_len, LOG_BUFFER_SIZE - tracer->log_msg_len, format, args);
    tracer->log_msg_len++;   // count \0 character
    va_end(args);

    if (tracer->log_file && (tracer->op_flags & ENABLE_FILE_LOG)) {
        
        if (tracer->op_flags & DISABLE_HDR_PRINTING) {
            fwrite (tracer->Logbuffer + HDR_SIZE, 1 , tracer->log_msg_len - HDR_SIZE, tracer->log_file);
        }
        else {
             fwrite (tracer->Logbuffer, 1 , tracer->log_msg_len, tracer->log_file);
        }

        flush_count++;
        if (flush_count % FLUSH_MAX == 0) {
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

    return tracer->bits & log_bit;
}

bool 
tracer_is_console_logging_enable (tracer_t *tracer) {

    return tracer->op_flags & ENABLE_CONSOLE_LOG;
}

bool 
tracer_is_file_logging_enable (tracer_t *tracer) {

    return tracer->op_flags & ENABLE_FILE_LOG;
}