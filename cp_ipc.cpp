#include <stdlib.h>
#include "graph.h"
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
        free(ips);
	}
}

static void
ipc_msg_destroy(event_dispatcher_t *ev, void *arg, uint32_t arg_size)  { delete (arg); }

static void
ipc_msg_free_after_use (event_dispatcher_t *ev, void *msg) {

	task_create_new_job (ev, 
									    msg,
										ipc_msg_destroy,
										TASK_ONE_SHOT,  
										TASK_PRIORITY_GARBAGE_COLLECTOR);
}

void 
cp_ipc_send (node_t *node, 
                        ips_major_code_t major_code,
                        uint32_t minor_code,
                        void *msg, 
                        uint32_t msg_size,
                        bool free_after_use) {

    ips_t *ips = (ips_t *)calloc(1, sizeof(ips_t));
    ips->major_code = major_code;
    ips->minor_code = minor_code;
    ips->msg = msg;
    ips->msg_size = msg_size;
    pkt_q_enqueue(EV(node), &node->cp_ipc_q, (char *)ips, sizeof(ips_t));
    if (free_after_use) ipc_msg_free_after_use (EV(node), msg);
}
