#ifndef __CP_IPC__
#define __CP_IPC__

#include "libs/gluethread/glthread.h"

#include <stdint.h>
#include <stdbool.h>
#include "cp_ipc_struct.h"

typedef struct node_ node_t;
typedef struct event_dispatcher_ event_dispatcher_t;

typedef struct ips_ {

    void *msg;
    void (*free_fn) (void *, void *);
    ips_major_code_t major_code;
    uint32_t minor_code;
    uint32_t msg_size;
    bool free_after_use;
    uint8_t flags;
    char padding[2];
    
}  ips_t;

typedef void (*ipc_recvr_fn_cbk)(node_t *node,
                                 ips_major_code_t major_code,
                                 uint32_t minor_code,
                                 void *msg,
                                 uint32_t msg_size);

typedef struct ipc_elem_ {

    ipc_recvr_fn_cbk cbk;
    glthread_t glue;
    uint32_t id;
    uint32_t minor_codes;

} __attribute__((aligned(8))) ipc_element_t;
GLTHREAD_TO_STRUCT(glue_to_ipc_element, ipc_element_t , glue);

void cp_ips_join(node_t *node,
                 ips_major_code_t major_code,
                 uint32_t minor_code,
                 ipc_recvr_fn_cbk fn);

void cp_ips_unjoin(node_t *node,
                   ips_major_code_t major_code,
                   ipc_recvr_fn_cbk fn);

void 
ipc_event_signal (event_dispatcher_t *ev_dis, void *data, uint32_t data_size) ;

void cp_ips_send(node_t *node,
                 ips_major_code_t major_code,
                 uint32_t minor_code,
                 void *msg,
                 uint32_t msg_size,
                 bool free_after_use,
                 void (*free_fn)(void *, void *));

#endif 
