
#include <stdio.h>
#include <arpa/inet.h>
#include "ipv6_utils.h"

char *
inet_ntop6 (ipv6_addr_t *addr, char *buffer) {

    inet_ntop(AF_INET6, &addr->addr, buffer, INET6_ADDRSTRLEN);
    return buffer;
}

void 
inet_pton6  (char *addr_str, ipv6_addr_t *addr) {

    inet_pton(AF_INET6, addr_str, &addr->addr);
}

const char *
end_fn_str(Srv6_endpcode_t end_fn) {

    switch (end_fn) {

        case END:
            return "END";
        case END_X:
            return "END_X";
        case END_T:
            return "END_T";
        case END_DX6:
            return "END_DX6";
        case END_DX4:
            return "END_DX4";
        case END_DT6:
            return "END_DT6";
        case END_DT4:
            return "END_DT4";
        default:
            return "UNKNOWN";
    }
}

const char *
flavor_str(uint8_t flavors) {

    switch (flavors) {

        case PSP:
            return "PSP";
        case USD:
            return "USD";
        case PSD:
            return "PSD";
        case PSP | USD:
            return "PSP | USD";
        case PSP | PSD:
            return "PSP | PSD";
        case USD | PSD:
            return "USD | PSD";
        case PSP | USD | PSD:
            return "PSP | USD | PSD";
        default:
            return "UNKNOWN";
    }
}