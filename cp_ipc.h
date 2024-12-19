#ifndef __CP_IPC__
#define __CP_IPC__

#include "gluethread/glthread.h"

#include <stdint.h>
#include <stdbool.h>

typedef struct node_ node_t;
typedef struct event_dispatcher_ event_dispatcher_t;

typedef enum ips_msg_code_ {

    IPC_IPV4_ROUTE,
    IPC_INTERFACE,
    IPC_GRE_TUNNEL,
    IPC_ACCESS_LST,
    IPC_MSG_TYPE_MAX

} ips_major_code_t;

typedef enum ips_sub_msg_code_ {

    IPC_SUB_ADD = 1,
    IPC_SUB_DEL = 2,
    IPC_SUB_UPDATE = 4,
    IPC_SUB_ADDRESS_CHANGE = 8,
    IPC_SUB_ADMIN_STATE_CHANGE = 16,
    IPC_SUB_BW_CHANGE = 32,
    IPC_SUB_MTU_CHANGE = 64,

    IPC_SUB_CODE_MAX

} ips_minor_code_t;

#define IPC_ALL_MINOR_UPDATES (0xFFFFFFFF)

typedef struct ips_ {

    ips_major_code_t major_code;
    ips_minor_code_t minor_code;
    void *msg;
    uint32_t msg_size;

}  ips_t;

typedef void (*ipc_recvr_fn_cbk) (node_t *node, 
                                                        ips_major_code_t major_code,
                                                        ips_minor_code_t minor_code,
                                                        void *msg,
                                                        uint32_t msg_size);

typedef struct ipc_elem_ {

    ipc_recvr_fn_cbk cbk;
    glthread_t glue;
    uint32_t id;
    uint32_t minor_codes;

} __attribute__((aligned(8))) ipc_element_t;
GLTHREAD_TO_STRUCT(glue_to_ipc_element, ipc_element_t , glue);


void 
cp_ipc_register (node_t *node, 
                           ips_major_code_t major_code,
                           uint32_t minor_code,
                           ipc_recvr_fn_cbk fn) ;

void 
cp_ipc_unregister (node_t *node, 
                           ips_major_code_t major_code,
                           ipc_recvr_fn_cbk fn) ;

void 
cp_ipc_event (event_dispatcher_t *ev_dis, void *data, uint32_t data_size) ;

void 
cp_ipc_send (node_t *node, 
                        ips_major_code_t major_code,
                        ips_minor_code_t minor_code,
                        void *msg, 
                        uint32_t msg_size,
                        bool free_after_use);

#endif 