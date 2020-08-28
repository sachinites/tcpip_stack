#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "gluethread/glthread.h"
#include "utils.h"
#include "tcpip_app_register.h"

extern glthread_t tcp_app_print_cb_db;

typedef struct tcp_app_cb_info_{

    uint32_t protocol_no;
    app_layer_cb app_cb;
    glthread_t glue;
} tcp_app_cb_info_t;
GLTHREAD_TO_STRUCT(glue_to_tcp_app_cb_info, 
    tcp_app_cb_info_t, glue);

typedef struct tcp_app_print_cb_info_{

    uint32_t protocol_no;
    char protocol_no_str[32];
    app_print_pkt_cb app_print_cb;
    glthread_t glue;
} tcp_app_print_cb_info_t;
GLTHREAD_TO_STRUCT(glue_to_tcp_app_print_cb_info, 
    tcp_app_print_cb_info_t, glue);

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

/*Function for print callbacks registration*/

static tcp_app_print_cb_info_t * 
tcp_stack_is_print_protocol_registered(
                      glthread_t *app_print_cb_db, 
                      uint32_t protocol_no, 
                      app_print_pkt_cb app_cb){

    glthread_t *curr;
    tcp_app_print_cb_info_t *tcp_app_print_cb_info;
    ITERATE_GLTHREAD_BEGIN(app_print_cb_db, curr){

        tcp_app_print_cb_info = glue_to_tcp_app_print_cb_info(curr);
        if(tcp_app_print_cb_info->protocol_no == protocol_no && 
            tcp_app_print_cb_info->app_print_cb == app_cb){
            return tcp_app_print_cb_info;
        }
    } ITERATE_GLTHREAD_END(app_print_cb_db, curr);
    return NULL;
}

char *
tcp_stack_get_print_str_protocol_number(uint32_t protocol_no){

    glthread_t *curr;
    tcp_app_print_cb_info_t *tcp_app_print_cb_info;

    ITERATE_GLTHREAD_BEGIN(&tcp_app_print_cb_db, curr){

        tcp_app_print_cb_info = glue_to_tcp_app_print_cb_info(curr);
        if(tcp_app_print_cb_info->protocol_no == protocol_no){
            return tcp_app_print_cb_info->protocol_no_str;
        }
    }  ITERATE_GLTHREAD_END(app_print_cb_db, curr);
    return NULL;
}

bool_t 
tcp_stack_register_print_callback(
                    uint32_t protocol_no,
                    char *protocol_no_str,
                    app_print_pkt_cb app_cb){
                   
    tcp_app_print_cb_info_t *tcp_app_print_cb_info;

    tcp_app_print_cb_info = tcp_stack_is_print_protocol_registered(
                &tcp_app_print_cb_db, protocol_no, app_cb);

    assert(!tcp_app_print_cb_info);

    tcp_app_print_cb_info = calloc(1, sizeof(tcp_app_print_cb_info_t));
    tcp_app_print_cb_info->protocol_no = protocol_no;
    strncpy(tcp_app_print_cb_info->protocol_no_str, protocol_no_str, 
        sizeof(tcp_app_print_cb_info->protocol_no_str));
    tcp_app_print_cb_info->app_print_cb = app_cb;
    init_glthread(&tcp_app_print_cb_info->glue);

    glthread_add_next(&tcp_app_print_cb_db, &tcp_app_print_cb_info->glue);
    return TRUE;
}

int
tcp_stack_invoke_app_print_callbacks(
                    glthread_t *app_print_cb_db, 
                    uint32_t protocol_no,
                    char *buff, char *pkt, 
                    uint32_t pkt_size){ 

     glthread_t *curr;
     tcp_app_print_cb_info_t *tcp_app_print_cb_info;

     ITERATE_GLTHREAD_BEGIN(app_print_cb_db, curr){

        tcp_app_print_cb_info = glue_to_tcp_app_print_cb_info(curr);
        if(tcp_app_print_cb_info->protocol_no == protocol_no){
            return ((tcp_app_print_cb_info->app_print_cb)
                (buff, pkt, pkt_size));
        }
     } ITERATE_GLTHREAD_END(app_print_cb_db, curr);
     return 0;
}


/*Interface Listener Registration*/

static glthread_t interface_listener_db;

typedef struct tcp_app_intf_listener_{

    interface_listerner_cb intf_lsnr_cb;
    glthread_t glue;
} tcp_app_intf_listener_t;
GLTHREAD_TO_STRUCT(glue_to_tcp_app_intf_listener, 
    tcp_app_intf_listener_t, glue);

void 
tcp_stack_register_interface_update_listener(
    interface_listerner_cb intf_lsnr_cb){

    tcp_app_intf_listener_t *tcp_app_intf_listener = calloc(1,
            sizeof(tcp_app_intf_listener_t));
    
    tcp_app_intf_listener->intf_lsnr_cb = 
            intf_lsnr_cb;

    init_glthread(&tcp_app_intf_listener->glue);
    glthread_add_next(&interface_listener_db, &tcp_app_intf_listener->glue);
}

void
tcp_stack_notify_interface_change_config(interface_t *intf, uint32_t flags){

    glthread_t *curr;
    tcp_app_intf_listener_t *tcp_app_intf_listener;

    ITERATE_GLTHREAD_BEGIN(&interface_listener_db, curr){

        tcp_app_intf_listener = glue_to_tcp_app_intf_listener(curr);
        (tcp_app_intf_listener->intf_lsnr_cb)(intf, flags);
    } ITERATE_GLTHREAD_END(&interface_listener_db, curr);
}


