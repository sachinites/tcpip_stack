  Topology : build_linear_topo

H1 -eth1--------------eth1- H2 -eth2----------------eth1-H3 -eth2----------------eth1- H4

PING TEST :

H4 :
config node H4 protocol source-packet-routing srv6 locator H4-LOC 2001:dbe8:4:: 48
config node H4 ipv6 route 2001:dbe8:4:: 48 srv6 endpoint end-sid

H3:
config node H3 protocol source-packet-routing srv6 locator H3-LOC 2001:dbe8:3:: 48
config node H3 ipv6 route 2001:dbe8:3:: 48 srv6 endpoint end-sid
config node H3 ipv6 route 2001:dbe8:4:: 48 srv6 endpoint end-sid nexthop eth2

H2:
config node H2 protocol source-packet-routing srv6 locator H2-LOC 2001:dbe8:2:: 48
config node H2 ipv6 route 2001:dbe8:2:: 48 srv6 endpoint end-sid
config node H2 ipv6 route 2001:dbe8:3:: 48 srv6 endpoint end-sid nexthop eth2

H1:
config node H1 protocol source-packet-routing srv6 locator H1-LOC 2001:dbe8:1:: 48
config node H1 ipv6 route 2001:dbe8:1:: 48 srv6 endpoint end-sid
config node H1 ipv6 route 2001:dbe8:2:: 48 srv6 endpoint end-sid nexthop eth1

logging configs :
=============
config node H1 debug l3fwd detail
config node H1 debug error
config node H1 traceoptions flag all
config node H2 debug l3fwd detail
config node H2 debug error
config node H2 traceoptions flag all
config node H3 debug l3fwd detail
config node H3 debug error
config node H3 traceoptions flag all
config node H4 debug l3fwd detail
config node H4 debug error
config node H4 traceoptions flag all

Test : 

H1:
run node H1 ping6 srv6 2001:dbe8:1:: 2001:dbe8:2:: 2001:dbe8:3:: 2001:dbe8:4::

Result : ping must succeed.


END_B6_ENCAP TEST :

H4 :
config node H4 protocol source-packet-routing srv6 locator H4-LOC 2001:dbe8:4:: 48
config node H4 ipv6 route 2001:dbe8:4:: 48 srv6 endpoint end-sid

H3:
config node H3 protocol source-packet-routing srv6 locator H3-LOC 2001:dbe8:3:: 48
config node H3 ipv6 route 2001:dbe8:3:: 48 srv6 endpoint end-sid
config node H3 ipv6 route 2001:dbe8:3:1:: 64 srv6 endpoint end-b6-encaps segment-list 2001:dbe8:4:: abcd::1 abcd::2 abcd::3
config node H3 ipv6 route 2001:dbe8:4:: 48 srv6 endpoint end-sid nexthop eth2

H2:
config node H2 protocol source-packet-routing srv6 locator H2-LOC 2001:dbe8:2:: 48
config node H2 ipv6 route 2001:dbe8:2:: 48 srv6 endpoint end-sid
config node H2 ipv6 route 2001:dbe8:3:: 48 srv6 endpoint end-sid nexthop eth2

H1:
config node H1 protocol source-packet-routing srv6 locator H1-LOC 2001:dbe8:1:: 48
config node H1 ipv6 route 2001:dbe8:1:: 48 srv6 endpoint end-sid
config node H1 ipv6 route 2001:dbe8:2:: 48 srv6 endpoint end-sid nexthop eth1

logging configs :
=============
config node H1 debug l3fwd detail
config node H1 debug error
config node H1 traceoptions flag all
config node H2 debug l3fwd detail
config node H2 debug error
config node H2 traceoptions flag all
config node H3 debug l3fwd detail
config node H3 debug error
config node H3 traceoptions flag all
config node H4 debug l3fwd detail
config node H4 debug error
config node H4 traceoptions flag all

Test : 

H1:
run node H1 ping6 srv6 2001:dbe8:1:: 2001:dbe8:2:: 2001:dbe8:3:1::

(check the egress pkt on H3 towards H4 )
H3(eth2) -->
Eth hdr : d4:ac:9b:62:a0:c9 -> ff:ff:ff:ff:ff:ff ETH_IP6 Vlan: 0 PL: 120B
IP6 Hdr : TL: 120B PRO: PROTO_SRH  fe80::d6ac:9bff:fe62:a0c9 -> 2001:dbe8:4:: ttl: 63
SRH Hdr : Nxt Hdr icmp6, Hdr_len 72, SL : 3
Seg 0 : abcd::3
Seg 1 : abcd::2
Seg 2 : abcd::1
Seg 3 : 2001:dbe8:4::
