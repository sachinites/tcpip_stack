#include "srv6_const.h"

Srv6_endpcode_t 
srv6_get_END_endpcode (uint8_t flavor) {

    switch (flavor) {

        case 0:
            return END;
        case PSP:
            return END_w_PSP;
        case USP:
            return END_w_USP;
        case USD:
            return END_w_USD;
        case PSP | USP:
            return END_w_PSP_USP;
        case PSP | USD:
            return END_w_PSP_USD;
        case USD | USP:
            return SRV6_END_FN_NONE;
        case PSP | USD | USP:
            return END_w_PSP_USP_USD;
        default:
            return SRV6_END_FN_NONE;
    }
}

Srv6_endpcode_t 
srv6_get_END_X_endpcode (uint8_t flavor) {

    switch (flavor) {

        case 0:
            return END_X;
        case PSP:
            return END_X_w_PSP;
        case USP:
            return END_X_w_USP;
        case USD:
            return END_X_w_USD;
        case PSP | USP:
            return END_X_w_PSP_USP;
        case PSP | USD:
            return END_X_w_PSP_USD;
        case USD | USP:
            return SRV6_END_FN_NONE;
        case PSP | USD | USP:
            return END_X_w_PSP_USP_USD;
        default:
            return SRV6_END_FN_NONE;
    }
}

 Srv6_endpcode_t 
srv6_split_endpcode (Srv6_endpcode_t endpcode, uint8_t *flavor) {
    
    Srv6_endpcode_t  ret; 

    switch (endpcode) {

        case END_w_PSP:
            *flavor = PSP;
            ret = END;
            break;
        case END_w_USP:
            *flavor = USP;
            ret = END;
            break;
        case END_w_USD:
            *flavor = USD;
            ret = END;
            break;
        case END_w_PSP_USP:
            *flavor = PSP | USP;
            ret = END;
            break;
        case END_w_PSP_USD:
            *flavor = PSP | USD;
            ret = END;
            break;
        case END_w_PSP_USP_USD:
            *flavor = PSP | USD | USP;
            ret = END;
            break;
        case END_X_w_PSP:
            *flavor = PSP;
            ret = END_X;
            break;
        case END_X_w_USP:
            *flavor = USP;
            ret = END_X;
            break;
        case END_X_w_USD:
            *flavor = USD;
            ret = END_X;
            break;
        case END_X_w_PSP_USP:
            *flavor = PSP | USP;
            ret = END_X;
            break;
        case END_X_w_PSP_USD:
            *flavor = PSP | USD;
            ret = END_X;
            break;
        case END_X_w_PSP_USP_USD:
            *flavor = PSP | USD | USP;
            ret = END_X;
            break;
        case END_T_w_PSP:
            *flavor = PSP;
            ret = END_T;
            break;
        case END_T_w_USP:
            *flavor = USP;
            ret = END_T;
            break;
        case END_T_w_USD:
            *flavor = USD;
            ret = END_T;
            break;
        case END_T_w_PSP_USP:
            *flavor = PSP | USP;
            ret = END_T;
            break;
        case END_T_w_PSP_USD:
            *flavor = PSP | USD;
            ret = END_T;
            break;
        case END_T_w_PSP_USP_USD:
            *flavor = PSP | USD | USP;
            ret = END_T;
            break;
        default:
            *flavor = 0;
            ret = endpcode;
    }

    return ret;
}

const char *
srv6_end_fn_str(Srv6_endpcode_t end_fn) {

    switch (end_fn) {

        case END:
            return "END";
        case END_w_PSP:
            return "END_w_PSP";
        case END_w_USP:
            return "END_w_USP";
        case END_w_PSP_USP:
            return "END_w_PSP_USP";
        case END_X:
            return "END_X";
        case END_X_w_PSP:
            return "END_X_w_PSP";
        case END_X_w_USP:
            return "END_X_w_USP";
        case END_X_w_PSP_USP:
            return "END_X_w_PSP_USP";
        case END_T:
            return "END_T";
        case END_T_w_PSP:
            return "END_T_w_PSP";
        case END_T_w_USP:
            return "END_T_w_USP";
        case END_T_w_PSP_USP:
            return "END_T_w_PSP_USP";
        case END_B6_ENCAP:
            return "END_B6_ENCAP";
        case END_BM:
            return "END_BM";
        case END_DX6:
            return "END_DX6";
        case END_DX4:
            return "END_DX4";
        case END_DT6:
            return "END_DT6";
        case END_DT4:
            return "END_DT4";
        case END_DT46:
            return "END_DT46";
        case END_DX2:
            return "END_DX2";
        case END_DX2V:
            return "END_DX2V";
        case END_DT2U:
            return "END_DT2U";
        case END_DT2M:
            return "END_DT2M";
        case END_B6_ENCAPS_Red:
            return "END_B6_ENCAPS_Red";
        case END_w_USD:
            return "END_w_USD";
        case END_w_PSP_USD:
            return "END_w_PSP_USD";
        case END_X_USP_USD:
            return "END_X_USP_USD";
        case END_w_PSP_USP_USD:
            return "END_w_PSP_USP_USD";
        case END_X_w_USD:
            return "END_X_w_USD";
        case END_X_w_PSP_USD:
            return "END_X_w_PSP_USD";
        case END_X_w_USP_USD:
            return "END_X_w_USP_USD";
        case END_X_w_PSP_USP_USD:
            return "END_X_w_PSP_USP_USD";
        case END_T_w_USD:
            return "END_T_w_USD";
        case END_T_w_PSP_USD:
            return "END_T_w_PSP_USD";
        case END_T_w_USP_USD:
            return "END_T_w_USP_USD";
        case END_T_w_PSP_USP_USD:
            return "END_T_w_PSP_USP_USD";
        default:
            return "Endfn not defined";
    }
}

const char *
srv6_flavor_str(uint8_t flavors) {

    switch (flavors) {

        case PSP:
            return "PSP";
        case USD:
            return "USD";
        case USP:
            return "USP";
        case PSP | USD:
            return "PSP | USD";
        case PSP | USP:
            return "PSP | USP";
        case USD | USP:
            return "USD | USP";
        case PSP | USD | USP:
            return "PSP | USD | USP";
        default:
            return "";
    }
}

