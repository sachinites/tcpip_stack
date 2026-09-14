Send Path :
===============

Local Route to BGP Advertisement:
==================================
bd_recv_mac_learning_cbk
    mac_vrf_evpn_route_type2_local_import
        evpn_route_export_to_bgp
                bgp_route_apply_to_gobgp
                    sf_gobgp_add_route
                        client->client.AddRoute(to_cpp_route_params(params));

Recvd From BGP to RTM installation:
==================================
GoBGP --> BGP EVPN global RIB --> Mac VRF RIBs ----> RTM ----> L2 FIB 

bgp_monitor_recv_global_rib_cbk
    pkt_q_enqueue
        bgp_global_rib_export_evpn_route_cb
            bgp_evpn_install_to_mac_vrf
                mac_vrf_evpn_route_type2_remote_import
                mac_vrf_evpn_route_type2_remote_delete


Recvd from BGP to Global RIB :
================================

bgp_global_rib_af_enable
    Subscribe : bgp_monitor_recv_global_rib_cbk

bgp_monitor_recv_global_rib_cbk
    pkt_q_enqueue
    . . .
    . . .
    bgp_route_pkt_q_cbk2
        bgp_global_rib_route_update
            bgp_global_rib_fill_attrs
            bgp_rib_route_add

==================================

Installation of remote MAC routes :

  GoBGP          show node R3 protocol bgp routes l2vpn-evpn mac
    |             PE Recvd - Entry point
    |
  --|--------------------SoftFireWall Begins here ----------------------------
    |
    V 
    EVPN Global RIB 
    |             show node R3 protocol bgp global-rib l2vpn-evpn
    |             Global RIB of EVPN MAC routes, Redistribute to MAC VRFs based on RT
    |
    V
    MAC VRF RIB  show node R3 protocol l2vpn evpn instance 1 mac-routes
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
 
