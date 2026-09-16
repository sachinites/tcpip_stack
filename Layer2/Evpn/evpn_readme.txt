
Show CLIs
=============
GoBGP                             : show node R3 protocol bgp routes l2vpn-evpn mac
BGP Global RIBs (Locally stored)  : show node R3 protocol bgp global-rib l2vpn-evpn
MAC VRF RIB                       : show node R3 protocol l2vpn evpn instance 1 mac-routes
RTM                               : show node R3 rtm 0.mac.10
MAC Table                         : show node R3 data-path bridge-domain 10 mac-address-table  
             
------------------------------------------

Type-2 MAC-only — LOCAL MAC
==============================
Call stack

BD MAC Learning
      │
      ▼
bd_recv_mac_learning_cbk()
      │
      ▼
mac_vrf_evpn_route_type2_local_import()
      │
      ├── hashtable_search(type2_rib, MAC)
      │
      ├── allocate evpn_exp_rt_t
      │
      ├── type  = EVPN_RT_TYPE_MAC_ONLY
      ├── flags = EVPN_RT_F_LOCAL
      ├── vtep  = local router-id
      ├── MAC   = learned MAC
      ├── IP    = 0
      └── label = BD vpn_svc_label
      │
      ▼
hashtable_insert(type2_rib)
      │
      ▼
evpn_route_export_to_bgp()
      │
      ▼
bgp_route_apply_to_gobgp()
      │
      ▼
sf_gobgp_add_route()
      │
      ▼
GoBGP AddRoute()
      │
      ▼
BGP EVPN UPDATE



Type-2 MAC-only — LOCAL withdrawal
==============================
Call stack

BD MAC delete / aging
        │
        ▼
mac_vrf_evpn_route_type2_delete()
        │
        ▼
lookup MAC in Type-2 RIB
        │
        ▼
route.flags == LOCAL
        │
        ▼
evpn_route_export_to_bgp(..., is_delete=true)
        │
        ▼
bgp_route_apply_to_gobgp(..., delete)
        │
        ▼
GoBGP withdraw
        │
        ▼
BGP EVPN UPDATE / withdrawal



Type-2 MAC-only — REMOTE MAC
==============================
Call stack

                    Remote PE
                       │
                       │ EVPN Type-2
                       ▼
                    GoBGP
                       │
                       ▼
             BGP Global EVPN RIB
                       │
                       ▼
        bgp_monitor_recv_global_rib_cbk()
                       │
                       ▼
                 pkt_q_enqueue()
                       │
                       ▼
       bgp_route_pkt_q_cbk2()
                       │
                       ▼
       bgp_global_rib_route_update()
                       │
                       ▼
       bgp_global_rib_export_evpn_route_cb()
                       │
                       ▼
        bgp_evpn_install_to_mac_vrf()
                       │
                       ▼
      mac_vrf_evpn_route_type2_remote_import()
                       │
             ┌─────────┴─────────┐
             │                   │
             ▼                   ▼
       MAC VRF Type-2 RIB       RTM
             │                   │
             │          cp_rtm_install_route_advanced()
             │                   │
             │                   ▼
             │               AF_MAC
             │                   │
             └───────────────────┘
                       │
                       ▼
                    L2 FIB
                       │
                       ▼
                    Datapath



Type-2 REMOTE withdrawal
==============================
Call stack

GoBGP withdrawal
       │
       ▼
BGP Global EVPN RIB
       │
       ▼
bgp_monitor_recv_global_rib_cbk()
       │
       ▼
pkt_q_enqueue()
       │
       ▼
bgp_global_rib_export_evpn_route_cb()
       │
       ▼
bgp_evpn_install_to_mac_vrf(... DELETE ...)
       │
       ▼
mac_vrf_evpn_route_type2_remote_delete()
       │
       ▼
hashtable_remove(type2_rib, MAC)
       │
       ▼
retrieve:
   remote VTEP
   EVPN label
       │
       ▼
cp_rtm_uninstall_route_advanced()
       │
       ▼
AF_MAC RTM
       │
       ▼
L2 forwarding state removed



Type-3 IMET — LOCAL
==============================
Call stack

EVPN configuration
       │
       ▼
evpn_connect_bd()
       │
       ├── associate EVI ↔ BD
       ├── assign EVI ID
       ├── generate RD
       ├── generate import RT
       ├── generate export RT
       ├── enable local MAC learning
       ├── create MAC VRF
       │
       ▼
mac_vrf_evpn_route_type3_local_import()
       │
       ▼
lookup local PE router-id
       │
       ▼
allocate evpn_exp_rt_t
       │
       ├── type = EVPN_RT_TYPE_IMET
       ├── flags = LOCAL
       ├── vtep_ip = local PE
       ├── pe_addr = local PE
       └── evpn_label = BD vpn_bum_label
       │
       ▼
insert type3_rib
       │
       ▼
evpn_route_export_to_bgp()
       │
       ▼
GoBGP AddRoute()
       │
       ▼
EVPN Type-3 IMET advertisement




Type-3 IMET — BGP export
==============================
Call stack

The same generic EVPN export function handles both Type-2 and Type-3.

evpn_route_export_to_bgp()
             │
             ▼
      evpn_rt->type ?
             │
       ┌─────┴─────┐
       │           │
    MAC_ONLY      IMET
       │           │
       ▼           ▼
   MAC params   IMET params
       │           │
       │           ├── pe_addr
       │           ├── prefix
       │           ├── eth_tag_id
       │           └── pmsi_label
       │
       └──────┬──────┘
              ▼
   bgp_route_apply_to_gobgp()
              │
              ▼
          GoBGP



Type-3 IMET — REMOTE
==============================
Call stack

Remote PE
    │
    │ Type-3 IMET
    ▼
GoBGP
    │
    ▼
BGP Global EVPN RIB
    │
    ▼
bgp_monitor_recv_global_rib_cbk()
    │
    ▼
pkt_q_enqueue()
    │
    ▼
bgp_global_rib_export_evpn_route_cb()
    │
    ▼
bgp_evpn_install_to_mac_vrf()
    │
    ▼
mac_vrf_evpn_route_type3_remote_import()
    │
    ▼
lookup PE address in type3_rib
    │
    ├── local exists → reject
    ├── duplicate → reject
    │
    ▼
create evpn_exp_rt_t
    │
    ├── type = IMET
    ├── flags = REMOTE
    ├── vtep_ip = remote VTEP
    ├── pe_addr = remote PE
    └── evpn_label = remote BUM/PMSI label
    │
    ▼
insert type3_rib
    │
    ▼
construct broadcast MAC
    │
    ▼
AF_MAC prefix = ff:ff:ff:ff:ff:ff /48
    │
    ▼
gateway = remote VTEP /32
    │
    ▼
cp_rtm_install_route_advanced()
    │
    ├── RTM_NH_ACTION_TUNNEL
    ├── remote VTEP
    └── BUM label
    │
    ▼
AF_MAC RTM



Type-3 LOCAL withdrawal
==============================
Call stack

evpn_disconnect_bd()
       │
       ▼
mac_vrf_evpn_route_type3_delete()
       │
       ▼
lookup local PE in type3_rib
       │
       ▼
evpn_route_export_to_bgp(... delete=true)
       │
       ▼
GoBGP withdraw
       │
       ▼
BGP EVPN Type-3 withdrawal
       │
       ▼
MAC VRF cleanup

The current evpn_disconnect_bd() explicitly calls the Type-3 delete before destroying the MAC VRF.




Type-3 REMOTE withdrawal
==============================
Call stack

BGP Type-3 withdrawal
        │
        ▼
BGP global RIB callback
        │
        ▼
bgp_evpn_install_to_mac_vrf(... delete ...)
        │
        ▼
mac_vrf_evpn_route_type3_remote_delete()
        │
        ▼
remove PE from type3_rib
        │
        ▼
broadcast MAC /48
        │
        ▼
cp_rtm_uninstall_route_advanced()
        │
        ▼
AF_MAC RTM
        │
        ▼
BUM forwarding path updated





