#ifndef __ISIS_ENUMS__
#define __ISIS_ENUMS__

typedef enum isis_tlv_record_advt_return_code_ {

    ISIS_TLV_RECORD_ADVT_SUCCESS,
    ISIS_TLV_RECORD_ADVT_ALREADY,
    ISIS_TLV_RECORD_ADVT_NO_SPACE,
    ISIS_TLV_RECORD_ADVT_NO_FRAG,
    ISIS_TLV_RECORD_ADVT_NOT_FOUND,
    ISIS_TLV_RECORD_ADVT_FAILED
}isis_advt_tlv_return_code_t;

typedef enum isis_tlv_wd_return_code_ {

    ISIS_TLV_WD_SUCCESS,
    ISIS_TLV_WD_FRAG_NOT_FOUND,
    ISIS_TLV_WD_TLV_NOT_FOUND,
    ISIS_TLV_WD_FAILED
}isis_tlv_wd_return_code_t;

typedef enum isis_job_type_ {

    ISIS_JOB_NONE = 0,
    ISIS_FRAG_REGEN_JOB = 1,
    ISIS_ALL_FRAG_REGEN_JOB = 2,
    ISIS_SPF_JOB = 4,
    ISIS_LSP_XMIT_INTF_JOB = 8,
    ISIS_ROUTE_CAL_JOB = 16,
    ISIS_JOB_MAX = 32

} isis_job_type_t;

static inline const char *
isis_job_type_str (isis_job_type_t job_type) {

    switch (job_type) {

        case ISIS_JOB_NONE:
            return "isis_job_none";
        case ISIS_FRAG_REGEN_JOB:
            return "isis_frag_regen_job";
        case ISIS_ALL_FRAG_REGEN_JOB:
            return "isis_all_frag_regen_job";
        case ISIS_SPF_JOB:
            return "isis_spf_job";
        case ISIS_LSP_XMIT_INTF_JOB:
            return "isis_lsp_xmit_intf_job";
        case ISIS_ROUTE_CAL_JOB:
            return "isis_route_cal_job";
        case ISIS_JOB_MAX:
            return "isis_job_max";
    }
    return "Null";
}


#endif 
