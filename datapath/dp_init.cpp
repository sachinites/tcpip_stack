#include "../router_init.h"
#include "../Tracer/tracer.h"

typedef  struct hashtable hashtable_t;

extern void dp_init_intf_hashtable (hashtable_t **ht);
extern void dp_init_vrf_hashtable (hashtable_t **ht);
extern int debug_infra_tracer_bits_to_str (char *buffer, uint64_t bits);

extern void dp_pkt_recvr_job_cbk(event_dispatcher_t *ev_dis, 
                void *pkt, uint32_t pkt_size);
extern void dp_pkt_xmit_intf_job_cbk (event_dispatcher_t *ev_dis, 
                void *pkt, uint32_t pkt_size);

extern void init_arp_table(arp_table_t **arp_table);
extern void init_mac_table(mac_table_t **mac_table);

extern bool LinuxRtr;


void 
dp_init (node_t *node) {

    char file_name[64];
    char ev_dis_name[EV_DIS_NAME_LEN];

    /* Initialize Data Plane Tracers*/
    memset(file_name, 0, sizeof(file_name));
    sprintf(file_name, "logs/%s-dp.txt", node->node_name);
    node->dptr = tracer_init (node->node_name, file_name, 
        node->node_name, STDOUT_FILENO, debug_infra_tracer_bits_to_str );
    tracer_enable_file_logging (node->dptr, true);

    /* Start Data Path Thread/Scheduler */
    snprintf (ev_dis_name, EV_DIS_NAME_LEN, "DP-%s", node->node_name);
    event_dispatcher_init(&node->dp_ev_dis, (const char *)ev_dis_name);
    event_dispatcher_run(&node->dp_ev_dis, LinuxRtr ? true : false);  /* Pin DP thread to high-perf core */
    node->dp_ev_dis.app_data = (void *)node;
    init_pkt_q(&node->dp_ev_dis, &node->dp_recvr_pkt_q, dp_pkt_recvr_job_cbk);
    init_pkt_q(&node->dp_ev_dis, &node->cp_to_dp_xmit_intf_pkt_q, dp_pkt_xmit_intf_job_cbk);
        
    /* Start DP Timer */
    node->dp_wt = init_wheel_timer(60, 1, TIMER_SECONDS);
    wt_set_user_data(node->dp_wt, EV_DP(node));
    start_wheel_timer(node->dp_wt);

    /* Start IPC Message Queue of Data Plane*/
    init_pkt_q (&node->dp_ev_dis, &node->dp_ipc_q, 0);

    init_arp_table(&(node->node_nw_prop.arp_table));
    init_mac_table(&(node->node_nw_prop.mac_table));

    dp_init_intf_hashtable (&node->dp_intf_ht);
    dp_init_vrf_hashtable (&node->dp_vrf_ht);
}