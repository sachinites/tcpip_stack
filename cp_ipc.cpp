#include <stdlib.h>
#include "router_init.h"
#include "cp_ipc.h"
#include "EventDispatcher/event_dispatcher.h"

void 
cp_ips_join (node_t *node, 
                           ips_major_code_t major_code,
                           uint32_t minor_code,
                           ipc_recvr_fn_cbk fn) {

    ipc_element_t *ipc_elem;

    glthread_t *head = &node->cp_ipc_data_base[major_code];

    ipc_elem = (ipc_element_t *)calloc (1, sizeof (ipc_element_t));

    ipc_elem->id = 0;
    ipc_elem->cbk = fn;
    init_glthread(&ipc_elem->glue);
    ipc_elem->minor_codes = minor_code;
    glthread_add_next (head, &ipc_elem->glue);
}

void 
cp_ips_unjoin (node_t *node, 
                           ips_major_code_t major_code,
                           ipc_recvr_fn_cbk fn) {

    glthread_t *curr;
    ipc_element_t *ipc_elem;

    glthread_t *head = &node->cp_ipc_data_base[major_code];

    ITERATE_GLTHREAD_BEGIN(head, curr) {

        ipc_elem = glue_to_ipc_element(curr);
        if (ipc_elem->cbk != fn) continue;
        remove_glthread (curr);
        free(ipc_elem);
        return;

    } ITERATE_GLTHREAD_END(head, curr);
    
}

static void 
 ipc_notify_ips (node_t *node, ips_t *ips) {

    glthread_t *curr;
    ipc_element_t *ipc_elem;

    if (ips->major_code >= IPC_MSG_TYPE_MAX) return;

    glthread_t *head = &node->cp_ipc_data_base[ips->major_code];

    ITERATE_GLTHREAD_BEGIN(head, curr) {

        ipc_elem = glue_to_ipc_element(curr);
        if (!(ipc_elem->minor_codes & ips->minor_code)) continue;
        ipc_elem->cbk (node, ips->major_code, ips->minor_code, ips->msg, ips->msg_size);

    } ITERATE_GLTHREAD_END(head, curr) ;

}

void 
ipc_event_signal (event_dispatcher_t *ev_dis, void *data, uint32_t data_size) {

    node_t *node = (node_t *)(ev_dis->app_data);

	ips_t *ips  =  (ips_t *)task_get_next_pkt(ev_dis, &data_size);
    
	if(!ips) return;
	
	for ( ; ips;  ips = (ips_t *) task_get_next_pkt(ev_dis, &data_size)) {
        ipc_notify_ips (node, ips);
	}
}

static void
ips_destroy(event_dispatcher_t *ev, void *arg, uint32_t arg_size)  { 

    ips_t *ips = (ips_t *)arg;
    node_t *node = (node_t *) (ev->app_data );

    if (!ips->free_after_use) {
        free (ips);
        return;
    }

    if (ips->free_fn)  ips->free_fn (node, ips->msg);
    else if (ips->msg ) delete ips->msg;
    
    ips->msg = NULL;
    free (ips);
}

static void
ipc_msg_free_after_use (event_dispatcher_t *ev,  ips_t *ips) {

	task_create_new_job (ev, 
									    (void *)ips,
										ips_destroy,
										TASK_ONE_SHOT,  
										TASK_PRIORITY_GARBAGE_COLLECTOR);
}

void 
cp_ips_send (node_t *node, 
                        ips_major_code_t major_code,
                        uint32_t minor_code,
                        void *msg, 
                        uint32_t msg_size,
                        bool free_after_use,
                        void (*free_fn)(node_t*, void *) ) {

    ips_t *ips = (ips_t *)calloc(1, sizeof(ips_t));
    ips->major_code = major_code;
    ips->minor_code = minor_code;
    ips->msg = msg;
    ips->msg_size = msg_size;
    ips->free_fn = free_fn;
    ips->free_after_use = free_after_use;
    pkt_q_enqueue(EV(node), &node->cp_ipc_q, (char *)ips, sizeof(ips_t));
    ipc_msg_free_after_use (EV(node), ips);
}
