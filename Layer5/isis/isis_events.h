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
    isis_event_lsp_time_out,
    #define ISIS_EVENT_LSP_TIMEOUT_LSP_BIT                           (1 << isis_event_lsp_time_out)
    /*lspdb update events end*/
    isis_event_periodic_lsp_generation,
    #define ISIS_EVENT_PERIODIC_LSP_GENERATION_BIT       (1 << isis_event_periodic_lsp_generation)
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
    isis_event_device_overload_config,
    #define ISIS_EVENT_DEVICE_OVERLOAD_BY_ADMIN_BIT  \
                                                                                                               (1 << isis_event_device_overload_config)
    isis_event_device_dynamic_overload,
    #define ISIS_EVENT_DEVICE_DYNAMIC_OVERLOAD_BIT  (1 <<   isis_event_device_dynamic_overload)
    isis_event_overload_timeout,
    #define ISIS_EVENT_OVERLOAD_TIMEOUT_BIT                   (1 << isis_event_overload_timeout)
    isis_event_route_rib_update,
    #define ISIS_EVENT_ROUTE_RIB_UPDATE_BIT                     (1 << isis_event_route_rib_update)
    isis_event_dis_changed,
    #define ISIS_EVENT_DIS_CHANGED_BIT                                 (1 << isis_event_dis_changed) 
    isis_event_discard_fragment,
    #define ISIS_EVENT_DISCARD_FRAGMENT_BIT                    (1 << isis_event_discard_fragment)
    isis_event_fragment_regen,
    #define ISIS_EVENT_FRAGMENT_REGEN_BIT                        (1 << isis_event_fragment_regen)
    isis_event_wait_list_tlv_advertised,
    #define ISIS_EVENT_WAIT_LIST_TLV_ADVERTISED_BIT     (1 << isis_event_wait_list_tlv_advertised)
    isis_event_tlv_wait_listed,
    #define ISIS_EVENT_TLV_WAIT_LISTED                                  (1 << isis_event_tlv_wait_listed)
    isis_event_tlv_added,
    #define ISIS_EVENT_TLV_ADD_BIT                                          (1 << isis_event_tlv_added)
    isis_event_tlv_removed,
    #define ISIS_EVENT_TLV_WITHDRAWL_BIT                          (1 << isis_event_tlv_removed)
    isis_event_full_lsp_regen,
    #define ISIS_EVENT_FULL_LSP_REGEN_BIT                          (1 <<  isis_event_full_lsp_regen)
    isis_event_max                                                                                 /* Do not cross more than 63 */
    #define ISIS_EVENT_MAX                                                            (1 << isis_event_max)
} isis_event_type_t;

const char *
isis_event_str(isis_event_type_t isis_event_type);

unsigned long
isis_event_to_event_bit(isis_event_type_t event_type);

#endif 
