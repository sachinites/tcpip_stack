#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "rtm_api.h"
#include "rtm_show.h"

int
main (int argc, char **argv) {

    rtm_module_init (); 
    rtm_initialize (RTM_DEFAULT_VRF, RTM_AF_IPV4, 0);
    rtm_t *rtm = rtm_get(RTM_DEFAULT_VRF, RTM_AF_IPV4, 0);
    assert (rtm);

    /* Install sample static route */
     rtm_prefix_t prefix;
     prefix.afi = RTM_AF_IPV4;
     prefix.u.v4_addr = 3232235776;
     prefix.prefix_len = 24;

    rtm_prefix_t gateway;
    gateway.afi = RTM_AF_IPV4;
    gateway.u.v4_addr = 167837953;
    gateway.prefix_len = 32;

    uint32_t oif_index = 1234;
    uint32_t cost = 100;

    rtm_error_t rc = rtm_install_static_route(rtm, &prefix, &gateway, oif_index, cost);

    if (rc != RTM_SUCCESS) {
        printf("Error installing static route: %s\n", rtm_error_to_string(rc));
        return -1;
    }

    /* Install one more static route*/
    prefix.u.v4_addr = 167837953;
    gateway.u.v4_addr = 3232235776;
    oif_index = 123;
    cost = 45;

    rc = rtm_install_static_route(rtm, &prefix, &gateway, oif_index, cost);

    if (rc != RTM_SUCCESS) {
        printf("Error installing static route: %s\n", rtm_error_to_string(rc));
        return -1;
    }

    /* Install one local  route*/
    prefix.u.v4_addr = 1677852929; // 100.2.0.0/32
    prefix.prefix_len = 32;
    oif_index = 123;
    cost = 45;

    rc = rtm_install_static_local_route(rtm, &prefix, oif_index, cost);

    if (rc != RTM_SUCCESS) {
        printf("Error installing static local route: %s\n", rtm_error_to_string(rc));
        return -1;
    }

    /* Install a BGP route using protocol route API */
    prefix.u.v4_addr = 168430081; // 10.10.0.1/32
    prefix.prefix_len = 32;
    gateway.u.v4_addr = 3232235777; // 192.168.0.1/32
    gateway.prefix_len = 32;
    oif_index = 5678;
    cost = 200;

    rc = rtm_install_protocol_route(rtm, &prefix, &gateway, 
                                     RTM_PROTO_BGP, RTM_PROTO_BGP_EXT, 
                                     0, oif_index, cost);

    if (rc != RTM_SUCCESS) {
        printf("Error installing BGP route: %s\n", rtm_error_to_string(rc));
        return -1;
    }

    /* Install an ISIS route using protocol route API */
    prefix.u.v4_addr = 2886729729; // 172.16.0.1/24
    prefix.prefix_len = 24;
    gateway.u.v4_addr = 168430082; // 10.10.0.2/32
    gateway.prefix_len = 32;
    oif_index = 9012;
    cost = 150;

    rc = rtm_install_protocol_route(rtm, &prefix, &gateway, 
                                     RTM_PROTO_ISIS, RTM_PROTO_L2_ISIS_INT, 
                                     1, oif_index, cost);

    if (rc != RTM_SUCCESS) {
        printf("Error installing ISIS route: %s\n", rtm_error_to_string(rc));
        return -1;
    }

    /* Install another BGP route with different instance */
    prefix.u.v4_addr = 168430337; // 10.11.0.1/24
    prefix.prefix_len = 24;
    gateway.u.v4_addr = 3232235778; // 192.168.0.2/32
    gateway.prefix_len = 32;
    oif_index = 5679;
    cost = 250;

    rc = rtm_install_protocol_route(rtm, &prefix, &gateway, 
                                     RTM_PROTO_BGP, RTM_PROTO_BGP_INT, 
                                     2, oif_index, cost);

    if (rc != RTM_SUCCESS) {
        printf("Error installing BGP internal route: %s\n", rtm_error_to_string(rc));
        return -1;
    }

    printf("\n===== IPv4 RTM - After Installing All Routes =====\n");
    rtm_show_rib_detail(rtm);
    rtm_show_nh_proto_info(rtm);
    
    /* Show detailed view of first 2 routes */
    rtm_show_rib_detail(rtm);

    printf("\n===== Testing MPLS/LDP Routes =====\n");
    rtm_initialize (RTM_DEFAULT_VRF, RTM_AF_LABEL, 0);
    rtm_t *rtm_mpls = rtm_get(RTM_DEFAULT_VRF, RTM_AF_LABEL, 0);
    assert (rtm_mpls);

    /* Test rtm_install_protocol_route_nh API with LDP MPLS route */
    printf("\n===== Testing rtm_install_protocol_route_nh API with LDP =====\n");
    
    // First, create or lookup the NH protocol info for LDP
    rtm_nh_proto_t *ldp_nh_proto = rtm_nh_proto_lookup(rtm_mpls, RTM_PROTO_LDP, 
                                                         RTM_SUB_PROTO_STATIC, 
                                                         0, rtm_mpls->vrf);
    
    if (!ldp_nh_proto) {
        rc = rtm_nh_proto_info_create(rtm_mpls, RTM_PROTO_LDP, RTM_SUB_PROTO_STATIC, 
                                       0, rtm_mpls->vrf, &ldp_nh_proto);
        if (rc != RTM_SUCCESS) {
            printf("Error creating LDP NH proto info: %s\n", rtm_error_to_string(rc));
            return -1;
        }
        // Add it to the tree
        rtm_nh_proto_add(rtm_mpls, ldp_nh_proto);
        printf("Created new LDP NH protocol info (instance 0)\n");
    } else {
        printf("Found existing LDP NH protocol info\n");
    }
    
    // Create temporary nexthop for LDP
    rtm_nh *temp_nh = (rtm_nh *)calloc(1, sizeof(rtm_nh));
    rtm_nh_initialize(temp_nh);
    
    // Configure the LDP nexthop
    *(RTM_PROTO_T*)&temp_nh->proto = RTM_PROTO_LDP;
    *(RTM_SUB_PROTO_T*)&temp_nh->sub_proto = RTM_SUB_PROTO_STATIC;
    temp_nh->ad = RTM_ADMIN_DIST_TNL_ENDP;  // AD = 2 for tunnel endpoints
    temp_nh->metric = 50;
    temp_nh->action = RTM_NH_ACTION_FORWARD;  // Forward with label swap
    
    // Nexthop is the next-hop IP address
    temp_nh->prefix.afi = RTM_AF_IPV4;
    temp_nh->prefix.u.v4_addr = 3232235779; // 192.168.0.3
    temp_nh->prefix.prefix_len = 32;
    temp_nh->outgoing_if = 9999;
    temp_nh->is_resolved = true;
    
    // Create MPLS label stack with SWAP operation
    temp_nh->label_stack = (lstack_t *)calloc(1, sizeof(lstack_t));
    temp_nh->label_stack->curr_index = 1;
    temp_nh->label_stack->labels[0].label_val = 2000;  // Outgoing label
    temp_nh->label_stack->labels[0].op = LBL_SWAP;     // SWAP operation
    
    // Route prefix is MPLS label (incoming label)
    rtm_prefix_t ldp_prefix;
    ldp_prefix.afi = RTM_AF_LABEL;           // MPLS AFI
    ldp_prefix.u.mpls_label = 1000;          // Incoming label
    ldp_prefix.prefix_len = 20;              // MPLS label is 20 bits
    
    // Pass both nexthop AND nh_proto - function will create its own heap copy of NH
    rc = rtm_install_protocol_route_nh(rtm_mpls, &ldp_prefix, temp_nh, ldp_nh_proto);
    
    if (rc != RTM_SUCCESS) {
        printf("Error installing LDP route via NH API: %s\n", rtm_error_to_string(rc));
        if (temp_nh->label_stack) free(temp_nh->label_stack);
        free(temp_nh);
        return -1;
    }
    
    // Free the temporary nexthop and label stack - function has made its own copy
    if (temp_nh->label_stack) free(temp_nh->label_stack);
    free(temp_nh);
    
    printf("Successfully installed LDP MPLS route (Label 1000 -> Swap to 2000)\n");
    printf("(Function internally allocated its own heap memory for nexthop and label stack)\n");

    printf("\n===== MPLS RTM - After Adding LDP Route =====\n");
    rtm_show_rib_detail(rtm_mpls);
    rtm_show_nh_proto_info(rtm_mpls);
    rtm_show_rib_detail(rtm_mpls);

    printf("\n===== Testing IPv6 Routes =====\n");
    rtm_initialize (RTM_DEFAULT_VRF, RTM_AF_IPV6, 0);
    rtm_t *rtmv6 = rtm_get(RTM_DEFAULT_VRF, RTM_AF_IPV6, 0);
    assert (rtmv6);

    /* Install IPv6 static route*/
    rtm_prefix_t v6prefix;
    v6prefix.afi = RTM_AF_IPV6;
    v6prefix.u.v6_addr[0] = 0x2001;
    v6prefix.u.v6_addr[1] = 0x0000;
    v6prefix.u.v6_addr[2] = 0x0000;
    v6prefix.u.v6_addr[3] = 0x0000;
    v6prefix.prefix_len = 120;

    rtm_prefix_t v6gateway;
    v6gateway.afi = RTM_AF_IPV6;
    v6gateway.u.v6_addr[0] = 0x3001;
    v6gateway.u.v6_addr[1] = 0x0000;
    v6gateway.u.v6_addr[2] = 0x0000;
    v6gateway.u.v6_addr[3] = 0x0000;
    v6gateway.prefix_len = 128;

    rc = rtm_install_static_route(rtmv6, &v6prefix, &v6gateway, oif_index, cost);
    if (rc != RTM_SUCCESS) {
        printf("Error installing static v6 route: %s\n", rtm_error_to_string(rc));
        return -1;
    }

    /* Install an IPv6 BGP route using protocol route API */
    v6prefix.u.v6_addr[0] = 0x2002;
    v6prefix.u.v6_addr[1] = 0x0000;
    v6prefix.u.v6_addr[2] = 0x0000;
    v6prefix.u.v6_addr[3] = 0x0001;
    v6prefix.prefix_len = 64;

    v6gateway.u.v6_addr[0] = 0x3002;
    v6gateway.u.v6_addr[1] = 0x0000;
    v6gateway.u.v6_addr[2] = 0x0000;
    v6gateway.u.v6_addr[3] = 0x0001;
    v6gateway.prefix_len = 128;

    rc = rtm_install_protocol_route(rtmv6, &v6prefix, &v6gateway,
                                     RTM_PROTO_BGP, RTM_PROTO_BGP_VPN,
                                     0, 7890, 300);

    if (rc != RTM_SUCCESS) {
        printf("Error installing IPv6 BGP VPN route: %s\n", rtm_error_to_string(rc));
        return -1;
    }

    printf("\n===== IPv6 RTM - After Installing All Routes =====\n");
    rtm_show_rib_detail(rtmv6);
    rtm_show_nh_proto_info(rtmv6);

    printf("\n===== Test Completed Successfully =====\n");
    return 0;
} 