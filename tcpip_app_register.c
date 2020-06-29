#include <assert.h>
#include <stdlib.h>
#include "gluethread/glthread.h"
#include "utils.h"
#include "tcpip_app_register.h"

typedef struct tcp_app_cb_info_{

    uint32_t protocol_no;
    app_layer_cb app_cb;
    glthread_t glue;
} tcp_app_cb_info_t;
GLTHREAD_TO_STRUCT(glue_to_tcp_app_cb_info, tcp_app_cb_info_t, glue);

static tcp_app_cb_info_t * 
tcp_stack_is_protocol_registered(glthread_t *app_cb_db, 
                      uint32_t protocol_no, 
                      app_layer_cb app_cb){

    glthread_t *curr;
    tcp_app_cb_info_t *tcp_app_cb_info;
    ITERATE_GLTHREAD_BEGIN(app_cb_db, curr){

        tcp_app_cb_info = glue_to_tcp_app_cb_info(curr);
        if(tcp_app_cb_info->protocol_no == protocol_no && 
            tcp_app_cb_info->app_cb == app_cb){
            return tcp_app_cb_info;
        }
    } ITERATE_GLTHREAD_END(app_cb_db, curr);
    return NULL;
}

bool_t 
tcp_stack_register_app_protocol(glthread_t *app_cb_db,
                    uint32_t protocol_no,
                    app_layer_cb app_cb){
                   
    tcp_app_cb_info_t *tcp_app_cb_info;

    tcp_app_cb_info = tcp_stack_is_protocol_registered(app_cb_db,
                protocol_no, app_cb);

    assert(!tcp_app_cb_info);

    tcp_app_cb_info = calloc(1, sizeof(tcp_app_cb_info_t));
    tcp_app_cb_info->protocol_no = protocol_no;
    tcp_app_cb_info->app_cb = app_cb;
    init_glthread(&tcp_app_cb_info->glue);

    glthread_add_next(app_cb_db, &tcp_app_cb_info->glue);
    return TRUE;
}

bool_t 
tcp_stack_unregister_app_protocol(glthread_t *app_cb_db,
                    uint32_t protocol_no,
                    app_layer_cb app_cb){
                    
    tcp_app_cb_info_t *tcp_app_cb_info = 
            tcp_stack_is_protocol_registered(app_cb_db,
                protocol_no, app_cb);

    if(!tcp_app_cb_info)
        return TRUE;
        
    remove_glthread(&tcp_app_cb_info->glue);
    free(tcp_app_cb_info);
    tcp_app_cb_info = NULL;
    return TRUE;
}

void
tcp_stack_invoke_app_callbacks(glthread_t *app_cb_db, 
                    uint32_t protocol_no,
                    node_t *node, 
                    interface_t *intf,
                    char *pkt, uint32_t pkt_size,
                    uint32_t flags){

     glthread_t *curr;
     tcp_app_cb_info_t *tcp_app_cb_info;

     ITERATE_GLTHREAD_BEGIN(app_cb_db, curr){

        tcp_app_cb_info = glue_to_tcp_app_cb_info(curr);
        if(tcp_app_cb_info->protocol_no == protocol_no){
            (tcp_app_cb_info->app_cb)(node, intf, pkt, pkt_size, flags);
        }
     } ITERATE_GLTHREAD_END(app_cb_db, curr);
}

