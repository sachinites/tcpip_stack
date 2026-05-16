#ifndef __ACL_BUILDER_H__
#define __ACL_BUILDER_H__

#include <stdint.h>
#include <pthread.h>
#include "../../libs/gluethread/glthread.h"

typedef struct access_list_ access_list_t;
typedef struct node_ node_t;
typedef struct task_ task_t;
typedef struct vrf_ vrf_t;
typedef struct mtrie_ mtrie_t;

typedef void (*acl_builder_notification_cbk)
    (node_t *, vrf_t *, access_list_t *, void *, mtrie_t *mtrie_out);

#pragma pack(push, 8)


typedef struct client_data_ {
 
    vrf_t *client_vrf;
    void *client_data;
    uint8_t numa_node;
    access_list_t *access_list;
    acl_builder_notification_cbk cbk;
    mtrie_t *mtrie_out;
    glthread_t glue;

} client_data_t; 
GLTHREAD_TO_STRUCT(glue_to_client_data, client_data_t, glue);

typedef struct acl_builder_ {

    /* Task for async processing */
    task_t *task;
    /* Node pointer for callbacks */
    node_t *node;

    client_data_t *current_client_data;

    pthread_mutex_t mutex;
    pthread_cond_t cv;
    Fglthread_t pending_access_list;

    pthread_t thread;

}acl_builder_t;

#pragma pack(pop)

void 
acl_builder_init (node_t *node, acl_builder_t **acl_builder);

/* Return 0 on success, 1 if Queued in Waiting list */
int8_t 
acl_builder_submit_access_list_build_request 
    (acl_builder_t *acl_builder, 
     access_list_t *acl, 
     vrf_t *client_vrf, void *client_data,
     acl_builder_notification_cbk cbk);


#endif 