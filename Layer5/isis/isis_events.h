#ifndef __ISIS_EVENTS__
#define __ISIS_EVENTS__

#include <assert.h>

typedef enum isis_events_ {

    isis_event_none,
    #define ISIS_EVENT_NONE_BIT                                           (1 << isis_event_none)
    isis_event_adj_state_changed,
    #define ISIS_EVENT_ADJ_STATE_CHANGED_BIT           (1 << isis_event_adj_state_changed)
    isis_event_admin_config_changed,
    #define ISIS_EVENT_ADMIN_CONFIG_CHANGED_BIT (1 << isis_event_admin_config_changed)
    isis_event_nbr_attribute_changed,
    #define ISIS_EVENT_NBR_ATTRIBUTE_CHANGED_BIT         (1 << isis_event_nbr_attribute_changed)
    isis_event_up_adj_deleted,
    #define ISIS_EVENT_UP_ADJ_DELETED_BIT                            ( 1 << isis_event_up_adj_deleted)
    /*lspdb update events begin*/
    isis_event_self_duplicate_lsp,
    #define ISIS_EVENT_SELF_DUPLICATE_LSP_BIT                     (1 << isis_event_self_duplicate_lsp)
    isis_event_self_fresh_lsp,
    #define ISIS_EVENT_SELF_FRESH_LSP_BIT                               (1 << isis_event_self_fresh_lsp)
    isis_event_self_new_lsp,
    #define ISIS_EVENT_SELF_NEW_LSP_BIT                                  (1 << isis_event_self_new_lsp)
    isis_event_self_old_lsp,
    #define ISIS_EVENT_SELF_OLD_LSP_BIT                                   (1 << isis_event_self_old_lsp)
    isis_event_non_local_duplicate_lsp,
    #define ISIS_EVENT_NON_LOCAL_DUPLICATE_LSP_BIT       (1 << isis_event_non_local_duplicate_lsp)
    isis_event_non_local_fresh_lsp,
    #define ISIS_EVENT_NON_LOCAL_FRESH_LSP_BIT                (1 << isis_event_non_local_fresh_lsp)
    isis_event_non_local_new_lsp,
    #define ISIS_EVENT_NON_LOCAL_NEW_LSP_BIT                   (1 << isis_event_non_local_new_lsp)
    isis_event_non_local_old_lsp,
    #define ISIS_EVENT_NON_LOCAL_OLD_LSP_BIT                    (1 << isis_event_non_local_old_lsp)
    /*lspdb update events end*/
    isis_event_on_demand_flood,
    #define ISIS_EVENT_ON_DEMAND_FLOOD_BIT                      (1 << isis_event_on_demand_flood)
    isis_event_periodic_lsp_generation,
    #define ISIS_EVENT_PERIODIC_LSP_GENERATION_BIT       (1 << isis_event_periodic_lsp_generation)
    isis_event_reconciliation_triggered,
    #define ISIS_EVENT_RECONCILIATION_TRIGGERED_BIT    (1 << isis_event_reconciliation_triggered)
    isis_event_reconciliation_restarted,
    #define ISIS_EVENT_RECONCILIATION_RESTARTED_BIT    (1 << isis_event_reconciliation_restarted)
    isis_event_reconciliation_exit,
    #define ISIS_EVENT_RECONCILIATION_EXIT_BIT                 (1 << isis_event_reconciliation_exit)
    isis_event_admin_action_db_clear,
    #define ISIS_EVENT_ADMIN_ACTION_DB_CLEAR_BIT        (1 << isis_event_admin_action_db_clear)
    /* SPF related events */
    isis_event_spf_job_scheduled,
    #define ISIS_EVENT_SPF_JOB_SCHEDULED_BIT                    (1 << isis_event_spf_job_scheduled)
    isis_event_spf_runs,
    #define ISIS_EVENT_SPF_RUNS_BIT                                          (1 << isis_event_spf_runs)
    isis_event_admin_action_shutdown_pending,
    #define ISIS_EVENT_ADMIN_ACTION_SHUTDOWN_PENDING_BIT \
                                                                                                               (1 << isis_event_admin_action_shutdown_pending)
    isis_event_device_overload_config_changed,
    #define ISIS_EVENT_DEVICE_OVERLOAD_CONFIG_CHANGED_BIT  \
                                                                                                               (1 << isis_event_device_overload_config_changed)
    isis_event_overload_timeout,
    #define ISIS_EVENT_OVERLOAD_TIMEOUT_BIT                   (1 << isis_event_overload_timeout)
    isis_event_max = isis_event_overload_timeout + 1                        /* Do not cross more than 63 */
    #define ISIS_EVENT_MAX                                                            (1 << isis_event_max)
} isis_event_type_t;

const char *
isis_event_str(isis_event_type_t isis_event_type);

unsigned long
isis_event_to_event_bit(isis_event_type_t event_type);

#endif 
