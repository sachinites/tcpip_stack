Send Path :
===============

Local Route to BGP Advertisement:
==================================
bd_recv_mac_learning_cbk
    mac_vrf_evpn_route_type2_local_import
        evpn_route_export_to_bgp
            bgp_evpn_type2_route_update
                bgp_route_apply_to_gobgp
                    sf_gobgp_add_route
                        client->client.AddRoute(to_cpp_route_params(params));

Recvd From BGP to RTM installation:
==================================
bgp_schedule_evpn_route_processing_job
    bgp_schedule_route_processing_job_common
        bgp_route_pkt_q_cbk
            bgp_evpn_remote_route_install
                mac_vrf_evpn_route_type2_remote_import
                    cp_rtm_install_route_advanced
                        rtm_l2_fib_update
                            cp2dp_bd_mac_table_entry_add_mpls

==================================

Installation of remote MAC routes :
    BGP          show node R3 protocol bgp routes l2vpn-evpn mac
    |             PE Recvd - Entry point
    |
    V 
    MAC VRF Global RIB 
    |             Global RIB of EVPN MAC routes, Redistribute to MAC VRFs based on RT
    |
    V
    MAC VRF RIB  show node R3 protocol l2vpn evpn instance 0 mac-routes
    |             Aggregation of EVPN MAC routes based on RTs 
    |
    V
    RTM          show node R3 rtm 0.mac.10
    |             Route Resolution
    |
 ---|----------- Data plane ----------------
    |             Forwarding
    V 
    MAC Table    show node R3 data-path bridge-domain 10 mac-address-table  
             
==================================
 
