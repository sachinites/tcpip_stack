  Topology : build_linear_topo

  H1 -eth1--------------eth1- H2 -eth2----------------eth1-H3 -eth2----------------eth1- H4
  
H4 :
config node H4 protocol source-packet-routing srv6 locator H4-LOC 2001:dbe8:4:: 64
config node H4 ipv6 route 2001:dbe8:4:: 64 srv6 endpoint end-sid

H3:
config node H3 protocol source-packet-routing srv6 locator H3-LOC 2001:dbe8:3:: 64
config node H3 ipv6 route 2001:dbe8:3:: 64 srv6 endpoint end-sid
config node H3 ipv6 route 2001:dbe8:4:: 64 srv6 endpoint end-sid nexthop eth2

H2:
config node H2 protocol source-packet-routing srv6 locator H2-LOC 2001:dbe8:2:: 64
config node H2 ipv6 route 2001:dbe8:2:: 64 srv6 endpoint end-sid
config node H2 ipv6 route 2001:dbe8:3:: 64 srv6 endpoint end-sid nexthop eth2

H1:
config node H1 protocol source-packet-routing srv6 locator H1-LOC 2001:dbe8:1:: 64
config node H1 ipv6 route 2001:dbe8:1:: 64 srv6 endpoint end-sid
config node H1 ipv6 route 2001:dbe8:2:: 64 srv6 endpoint end-sid nexthop eth1

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

