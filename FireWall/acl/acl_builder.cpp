#include <stdio.h>
#include <stdbool.h>
#include <sched.h>
#include <unistd.h>

#include "../../libs/mtrie/mtrie.h"
#include "../../libs/LinuxMemoryManager/uapi_mm.h"
#include "../../libs/EventDispatcher/event_dispatcher.h"

#include "acl_builder.h"
#include "acldb.h"
#include "../../net.h"


/* Scan cpufreq to find the logical CPU with the highest advertised max
 * frequency.  On hybrid architectures (Intel P/E-cores, ARM big.LITTLE)
 * this reliably identifies a performance core.  Falls back to CPU 0 when
 * cpufreq sysfs is absent (VMs, certain embedded targets). */
static int
acl_builder_get_high_perf_core (void) {

    int cpu, best_cpu = 0;
    unsigned long freq, best_freq = 0;
    char path[80];
    FILE *fp;
    int ncpus = (int)sysconf(_SC_NPROCESSORS_CONF);

    for (cpu = 0; cpu < ncpus; cpu++) {

        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", cpu);
        fp = fopen(path, "r");
        if (!fp) continue;

        if (fscanf(fp, "%lu", &freq) == 1 && freq > best_freq) {
            best_freq = freq;
            best_cpu  = cpu;
        }
        fclose(fp);
    }

    return best_cpu;
}

static mtrie_t *
acl_builder_rebuild_access_list (acl_builder_t *acl_builder) {

    glthread_t *curr;
    mtrie_node_t *mnode;
    mtrie_ops_result_code_t rc;
    acl_tcam_t tcam_entry_template;
    acl_tcam_iterator_t src_it, dst_it, src_port_it, dst_port_it;

    access_list_t *access_list = acl_builder->current_client_data->access_list;

    mtrie_t *new_mtrie = access_list_get_new_tcam_mtrie();

    bitmap_init(&tcam_entry_template.prefix, ACL_PREFIX_LEN);
    bitmap_init(&tcam_entry_template.mask, ACL_PREFIX_LEN);
    init_glthread(&tcam_entry_template.glue);

    ITERATE_GLTHREAD_BEGIN(&access_list->head, curr) {

        acl_entry_t *acl_entry = glthread_to_acl_entry(curr);

        acl_tcam_iterator_init(acl_entry, &src_it,      acl_iterator_src_addr);
        acl_tcam_iterator_init(acl_entry, &dst_it,      acl_iterator_dst_addr);
        acl_tcam_iterator_init(acl_entry, &src_port_it, acl_iterator_src_port);
        acl_tcam_iterator_init(acl_entry, &dst_port_it, acl_iterator_dst_port);

        acl_tcam_iterator_first(&src_it);
        acl_tcam_iterator_first(&dst_it);
        acl_tcam_iterator_first(&src_port_it);
        acl_tcam_iterator_first(&dst_port_it);

        do {
            acl_get_member_tcam_entry(acl_entry,
                                      &src_it, &src_port_it,
                                      &dst_it, &dst_port_it,
                                      &tcam_entry_template);

            rc = mtrie_insert_prefix(new_mtrie,
                                     &tcam_entry_template.prefix,
                                     &tcam_entry_template.mask,
                                     ACL_PREFIX_LEN,
                                     &mnode);
            switch (rc) {
                case MTRIE_INSERT_SUCCESS:
                    access_list_mtrie_allocate_mnode_data(mnode, (void *)acl_entry);
                    break;
                case MTRIE_INSERT_DUPLICATE:
                    access_list_mtrie_duplicate_entry_found(mnode, (void *)acl_entry);
                    break;
                case MTRIE_INSERT_FAILED:
                    assert(0);
            }

        } while (acl_iterators_increment(&src_it, &dst_it, &src_port_it, &dst_port_it));

        acl_tcam_iterator_deinit(&src_it);
        acl_tcam_iterator_deinit(&dst_it);
        acl_tcam_iterator_deinit(&src_port_it);
        acl_tcam_iterator_deinit(&dst_port_it);

    } ITERATE_GLTHREAD_END(&access_list->head, curr);

    bitmap_free_internal(&tcam_entry_template.prefix);
    bitmap_free_internal(&tcam_entry_template.mask);

    return new_mtrie;
}

static void
acl_builder_notify_cbk(event_dispatcher_t *ev_dis, 
                       void *arg, 
                       uint32_t arg_size) {

    node_t *node = (node_t *)ev_dis->app_data;
    client_data_t *client_data = (client_data_t *)arg;

    client_data->cbk(node, client_data->client_vrf, 
                     client_data->access_list,
                     client_data->client_data, client_data->mtrie_out);
                                      
    client_data->access_list->build_in_progress = false;

    /* Notify to all clients here */
    access_list_notify_clients (node, client_data->access_list);

    access_list_dereference (node, client_data->access_list);
    XFREE(client_data);
}

static void *
acl_builder_thread_func (void *arg) {

    mtrie_t *new_mtrie = NULL;
    acl_builder_t *acl_builder = (acl_builder_t *)arg;

    while (1) {

        pthread_mutex_lock (&acl_builder->mutex);

        while (acl_builder->current_client_data == NULL) {
            pthread_cond_wait (&acl_builder->cv, &acl_builder->mutex);
        }

        pthread_mutex_unlock (&acl_builder->mutex);

        acl_builder->current_client_data->mtrie_out =
            acl_builder_rebuild_access_list (acl_builder);

        /* Notify back to the client */
        task_create_new_job(EV(acl_builder->node),
                            (void *)acl_builder->current_client_data,
                            acl_builder_notify_cbk, 
                            TASK_ONE_SHOT, TASK_PRIORITY_COMPUTE);

        /* Clear the current client data */
        pthread_mutex_lock (&acl_builder->mutex);

        acl_builder->current_client_data = NULL;

        /* Load the new request from pending list if any */
        glthread_t *curr = dequeue_glthread_first (&acl_builder->pending_access_list.head);

        if (!curr) {
            pthread_mutex_unlock (&acl_builder->mutex);
            continue;
        }

        client_data_t *next_client = glue_to_client_data (curr);
        acl_builder->current_client_data =  next_client;

        pthread_mutex_unlock (&acl_builder->mutex); 
    }
    return NULL;
}

void 
acl_builder_init (node_t *node, acl_builder_t **_acl_builder) {

    acl_builder_t *acl_builder = (acl_builder_t *)XCALLOC(0, 1, acl_builder_t);
    *_acl_builder = acl_builder;

    acl_builder->task = NULL;
    acl_builder->node = node;
    acl_builder->current_client_data = NULL;
    pthread_mutex_init(&acl_builder->mutex, NULL);
    pthread_cond_init (&acl_builder->cv, NULL);
    init_Fglthread(&acl_builder->pending_access_list);
    pthread_create(&acl_builder->thread, NULL, 
        acl_builder_thread_func, (void *)acl_builder);

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(acl_builder_get_high_perf_core(), &cpuset);
    pthread_setaffinity_np(acl_builder->thread, sizeof(cpuset), &cpuset);
}

int8_t 
acl_builder_submit_access_list_build_request (
                        acl_builder_t *acl_builder, 
                        access_list_t *access_list, 
                        vrf_t *client_vrf, 
                        void *client_pvt_data,
                        acl_builder_notification_cbk cbk) {

    client_data_t *client_data;

    if (access_list->build_in_progress) return -1;

    access_list->build_in_progress = true;
    access_list_reference (access_list);

    pthread_mutex_lock (&acl_builder->mutex);

    client_data = (client_data_t *)XCALLOC2(0, 1, client_data_t);
    client_data->access_list = access_list;
    client_data->client_vrf = client_vrf;
    client_data->client_data = client_pvt_data;
    client_data->cbk = cbk;
    client_data->numa_node = 0;
    client_data->mtrie_out = NULL;
    init_glthread(&client_data->glue);

    if (acl_builder->current_client_data) {

        Fglthread_add_last(&acl_builder->pending_access_list, &client_data->glue);
        pthread_mutex_unlock (&acl_builder->mutex);
        return 1;
    }

    acl_builder->current_client_data = client_data;
    pthread_cond_signal(&acl_builder->cv);
    pthread_mutex_unlock (&acl_builder->mutex);
    return 0;
}