export CC=g++
#SANITIZER_FLAGS=-fsanitize=address,undefined
SANITIZER_FLAGS=
export CFLAGS=-g -Wcast-align -fpermissive -Wall -Wextra -Wmissing-prototypes -Wold-style-definition -Wold-style-declaration -gdwarf-2 -g3 -Wignored-qualifiers -g ${SANITIZER_FLAGS}
TARGET:tcpstack.exe pkt_gen.exe

# Install external dependent libs :   sudo apt-get install libpq-dev

# Proto Libs
ISIS_LIB=Layer3/isis/libisis.a
ISIS_LIB_PATH=-LLayer3/isis -lisis
# proto Libs
SRV6_LIB=Layer3/SegmentRouting/SRv6/libsrv6.a
SRV6_LIB_PATH=-LLayer3/SegmentRouting/SRv6 -lsrv6
# proto Libs
LFA_LIB=Layer3/LFA/liblfa.a
LFA_LIB_PATH=-LLayer3/LFA -llfa

LIBS= ${ISIS_LIB_PATH} \
			${SRV6_LIB_PATH} \
			${LFA_LIB_PATH} \
			-LCLIBuilder -lclibuilder \
		    -LLinuxMemoryManager -lmm \
			-LFSMImplementation -lfsm \
			-LFireWall -lasa \
			-L../RDBMSImplementation/SqlParser -lsqlapi \
			-L../RDBMSImplementation/SqlParser -ldbms \
			-L../MathExpressionParser -lMexpr \
			-Ldatapath -ldp \
			-LRTM -lrtm \
			-LFIB -lfib \
			-lpthread \
			-lpq \
   		    -lrt \
			-lfl \
			-lm \
			-lncurses \

OBJS=gluethread/glthread.o \
		  BitOp/bitmap.o \
		  stack/stack.o \
		  Tree/avl.o	   \
		  mtrie/mtrie.o	   \
		  router_init.o 		   \
		  cli_interface.o \
		  topologies.o	   \
		  net.o			   \
		  comm.o		   \
		  Layer2/layer2.o  \
		  Layer2/transport_svc.o  \
		  Layer2/arp.o	   \
		  Layer2/mac_table.o \
		  Layer2/vxlan/dp/vxlan_dp.o \
		  Layer2/vxlan/cp/vlan_vni_mapping.o \
		  Layer2/vxlan/cp/vxlan_cli.o \
		  Layer2/vxlan/dp/vlan_vni_ht.o \
		  Layer3/layer3.o  \
		  Layer3/gre-tunneling/grecli.o \
		  Layer3/gre-tunneling/gre.o \
		  Layer3/rt_table/nexthop.o \
		  Layer3/netfilter.o \
		  Layer3/ipv6/ipv6cli.o \
		  Layer3/ipv6/ipv6_utils.o \
		  Layer3/ipv6/v6nexthop.o \
		  Layer3/ipv6/ipv6_fwd.o \
		  Layer3/mpls_cli.o \
		  Layer4/layer4.o  \
		  Layer4/udp.o  \
		  Layer5/layer5.o  \
		  nwcli.o		   \
		  utils.o		   \
		  cp_ipc.o \
		  Layer2/l2switch.o \
          libtimer/WheelTimer.o   \
          libtimer/timerlib.o   \
		  libtimer/timedef.o \
		  Tracer/tracer.o \
		  tcp_stack_init.o	\
		  pkt_block.o \
		  tcp_ip_trace.o	\
 		  tcpip_notif.o \
		  configdb.o \
		  notif.o	\
		  EventDispatcher/event_dispatcher.o \
		  tcp_ip_default_traps.o \
		  ted/ted.o \
		  tcp_stack_mem_init.o \
		  packet-tracer/pkt_tracer.o \
		  prefix-list/prefixlst.o \
		  c-hashtable/hashtable.o \
		  c-hashtable/hashtable_itr.o \
		  Threads/refcount.o \
		  Interface/Interface.o \
		  Interface/InterfaceUApi.o \
		  Interface/InterfaceCli.o \
		  PostgresLibpq/postgresLib.o \
		  common/cp2dp.o \
		  common/cmn_prefix.o \
		  lmm_reg.o \
		  sql_cli.o \
		  Linux/LinuxInterface.o \
		  RTM/rtm_nb_integ.o \
		  vrf/vrf_cli.cpp \
		  vrf/vrf.cpp \
		  Layer3/SegmentRouting/SR-MPLS/srgb.o \
		  


lmm_reg.o:lmm_reg.c
	${CC} ${CFLAGS} -c -I LinuxMemoryManager lmm_reg.c -o lmm_reg.o

sql_cli.o:sql_cli.cpp
	${CC} ${CFLAGS} -c sql_cli.cpp -o sql_cli.o

Layer2/vxlan/cp/vlan_vni_mapping.o:Layer2/vxlan/cp/vlan_vni_mapping.c
	${CC} ${CFLAGS} -c -I Layer2/vxlan Layer2/vxlan/cp/vlan_vni_mapping.c -o Layer2/vxlan/cp/vlan_vni_mapping.o

Layer2/vxlan/cp/vxlan_cli.o:Layer2/vxlan/cp/vxlan_cli.c 
	${CC} ${CFLAGS} -c -I . Layer2/vxlan/cp/vxlan_cli.c -o Layer2/vxlan/cp/vxlan_cli.o

Layer2/vxlan/dp/vlan_vni_ht.o:Layer2/vxlan/dp/vlan_vni_ht.c
	${CC} ${CFLAGS} -c -I . Layer2/vxlan/dp/vlan_vni_ht.c -o Layer2/vxlan/dp/vlan_vni_ht.o

Threads/refcount.o:Threads/refcount.c
	${CC} ${CFLAGS} -c Threads/refcount.c -o Threads/refcount.o

Tracer/tracer.o:Tracer/tracer.cpp
	${CC} ${CFLAGS} -I Tracer -c Tracer/tracer.cpp -o Tracer/tracer.o

ted/ted.o:ted/ted.c
	${CC} ${CFLAGS} -c -I . ted/ted.c -o ted/ted.o

cp_ipc.o:cp_ipc.cpp
	${CC} ${CFLAGS} -c -I . cp_ipc.cpp -o cp_ipc.o

prefix-list/prefixlst.o:prefix-list/prefixlst.c
	${CC} ${CFLAGS} -c -I . prefix-list/prefixlst.c -o prefix-list/prefixlst.o

tcp_ip_default_traps.o:tcp_ip_default_traps.c
	${CC} ${CFLAGS} -c -I . tcp_ip_default_traps.c -o tcp_ip_default_traps.o

tcp_stack_mem_init.o:tcp_stack_mem_init.c
	${CC} ${CFLAGS} -c -I . tcp_stack_mem_init.c -o tcp_stack_mem_init.o

EventDispatcher/event_dispatcher.o:EventDispatcher/event_dispatcher.c
	${CC} ${CFLAGS} -c -I EventDispatcher -I gluethread EventDispatcher/event_dispatcher.c -o EventDispatcher/event_dispatcher.o

pkt_gen.exe:pkt_gen.o utils.o
	${CC} ${CFLAGS} -I tcp_public.h pkt_gen.o utils.o -o pkt_gen.exe
	@echo "pkt_gen.exe Build Finished"
	
pkt_gen.o:pkt_gen.c
	${CC} ${CFLAGS} -c pkt_gen.c -o pkt_gen.o

tcpstack.exe:main.o ${OBJS} ${ISIS_LIB} ${SRV6_LIB} ${LFA_LIB} CLIBuilder/clibuilder.a LinuxMemoryManager/libmm.a FSMImplementation/libfsm.a FireWall/libasa.a RTM/librtm.a FIB/libfib.a datapath/libdp.a
	${CC} ${CFLAGS} main.o ../RDBMSImplementation/SqlParser/SqlToMexprEnumMapper.o ${OBJS}  ${LIBS} -o tcpstack.exe
	@echo "tcpstack.exe Build Finished"

notif.o:notif.c
	${CC} ${CFLAGS} -c -I gluethread -I . notif.c -o notif.o

tcpip_notif.o:tcpip_notif.c
	${CC} ${CFLAGS} -c -I gluethread -I . tcpip_notif.c -o tcpip_notif.o

main.o:main.c
	${CC} ${CFLAGS} -c main.c -o main.o

gluethread/glthread.o:gluethread/glthread.c
	${CC} ${CFLAGS} -c -I gluethread gluethread/glthread.c -o gluethread/glthread.o

Tree/avl.o:Tree/avl.c
	${CC} ${CFLAGS} -c -I Tree Tree/avl.c -o Tree/avl.o

mtrie/mtrie.o:mtrie/mtrie.c
	${CC} ${CFLAGS} -c -I mtrie mtrie/mtrie.c -o mtrie/mtrie.o

libtimer/WheelTimer.o:libtimer/WheelTimer.c
	${CC} ${CFLAGS} -c -I gluethread -I libtimer libtimer/WheelTimer.c -o libtimer/WheelTimer.o
libtimer/timerlib.o:libtimer/timerlib.c
	${CC} ${CFLAGS} -c -I gluethread -I libtimer libtimer/timerlib.c -o libtimer/timerlib.o
libtimer/timedef.o:libtimer/timedef.c
	${CC} ${CFLAGS} -c -I libtimer libtimer/timedef.c -o libtimer/timedef.o	

tcp_stack_init.o:tcp_stack_init.c
	${CC} ${CFLAGS} -c tcp_stack_init.c -o tcp_stack_init.o

router_init.o:router_init.c
	${CC} ${CFLAGS} -c -I . router_init.c -o router_init.o

common/cp2dp.o:common/cp2dp.cpp
	${CC} ${CFLAGS} -c -I . common/cp2dp.cpp -o common/cp2dp.o

common/cmn_prefix.o:common/cmn_prefix.cpp
	${CC} ${CFLAGS} -c -I . common/cmn_prefix.cpp -o common/cmn_prefix.o

cli_interface.o:cli_interface.c
	${CC} ${CFLAGS} -c -I . cli_interface.c -o cli_interface.o

topologies.o:topologies.c
	${CC} ${CFLAGS} -c -I . topologies.c -o topologies.o

net.o:net.c
	${CC} ${CFLAGS} -c -I . net.c -o net.o

configdb.o:configdb.cpp
	${CC} ${CFLAGS} -c -I . configdb.cpp -o configdb.o

pkt_block.o:pkt_block.c
	${CC} ${CFLAGS} -c -I . pkt_block.c -o pkt_block.o

comm.o:comm.c
	${CC} ${CFLAGS} -c -I . comm.c -o comm.o

tcp_ip_trace.o:tcp_ip_trace.c
	${CC} ${CFLAGS} -c -I . tcp_ip_trace.c -o tcp_ip_trace.o

Layer2/layer2.o:Layer2/layer2.c
	${CC} ${CFLAGS} -c -I . Layer2/layer2.c -o Layer2/layer2.o

Layer2/arp.o:Layer2/arp.c
	${CC} ${CFLAGS} -c -I . Layer2/arp.c -o Layer2/arp.o

Layer2/l2switch.o:Layer2/l2switch.c
	${CC} ${CFLAGS} -c -I . Layer2/l2switch.c -o Layer2/l2switch.o

Layer2/transport_svc.o:Layer2/transport_svc.cpp 
	${CC} ${CFLAGS} -c -I . Layer2/transport_svc.cpp -o Layer2/transport_svc.o

Layer2/mac_table.o:Layer2/mac_table.cpp
	${CC} ${CFLAGS} -c -I . Layer2/mac_table.cpp -o Layer2/mac_table.o

Layer3/layer3.o:Layer3/layer3.c
	${CC} ${CFLAGS} -c -I . Layer3/layer3.c -o Layer3/layer3.o

Layer3/rt_table/nexthop.o:Layer3/rt_table/nexthop.c
	${CC} ${CFLAGS} -c -I . Layer3/rt_table/nexthop.c -o Layer3/rt_table/nexthop.o

Layer3/mpls_cli.o:Layer3/mpls_cli.cpp
	${CC} ${CFLAGS} -c -I . Layer3/mpls_cli.cpp -o Layer3/mpls_cli.o

Layer3/netfilter.o:Layer3/netfilter.c
	${CC} ${CFLAGS} -c -I . Layer3/netfilter.c -o Layer3/netfilter.o

Layer4/layer4.o:Layer4/layer4.c
	${CC} ${CFLAGS} -c -I . Layer4/layer4.c -o Layer4/layer4.o

Layer4/udp.o:Layer4/udp.c
	${CC} ${CFLAGS} -c -I . Layer4/udp.c -o Layer4/udp.o	
	
Layer5/layer5.o:Layer5/layer5.c
	${CC} ${CFLAGS} -c -I . Layer5/layer5.c -o Layer5/layer5.o

nwcli.o:nwcli.c
	${CC} ${CFLAGS} -c -I . nwcli.c  -o nwcli.o

utils.o:utils.c
	${CC} ${CFLAGS} -c -I . utils.c -o utils.o

BitOp/bitmap.o:BitOp/bitmap.c
	${CC} ${CFLAGS} -c BitOp/bitmap.c -o BitOp/bitmap.o

stack/stack.o:stack/stack.c
	${CC} ${CFLAGS} -c stack/stack.c -o stack/stack.o

packet-tracer/pkt_tracer.o:packet-tracer/pkt_tracer.c
	${CC} ${CFLAGS} -c packet-tracer/pkt_tracer.c -o packet-tracer/pkt_tracer.o

#hasTable Files
c-hashtable/hashtable.o:c-hashtable/hashtable.c
	${CC} ${CFLAGS} -c c-hashtable/hashtable.c -o c-hashtable/hashtable.o

c-hashtable/hashtable_itr.o:c-hashtable/hashtable_itr.c
	${CC} ${CFLAGS} -c c-hashtable/hashtable_itr.c -o c-hashtable/hashtable_itr.o

#GRE files
Layer3/gre-tunneling/grecli.o:Layer3/gre-tunneling/grecli.cpp
	${CC} ${CFLAGS} -c -I CLIBuilder -I Layer3/gre-tunneling Layer3/gre-tunneling/grecli.cpp -o Layer3/gre-tunneling/grecli.o
Layer3/gre-tunneling/gre.o:Layer3/gre-tunneling/gre.cpp
	${CC} ${CFLAGS} -c -I CLIBuilder -I Layer3/gre-tunneling Layer3/gre-tunneling/gre.cpp -o Layer3/gre-tunneling/gre.o

#OOPs Interface Files 
Interface/Interface.o:Interface/Interface.cpp
	${CC} ${CFLAGS} -c Interface/Interface.cpp -o Interface/Interface.o

Interface/InterfaceUApi.o:Interface/InterfaceUApi.cpp
	${CC} ${CFLAGS} -c Interface/InterfaceUApi.cpp -o Interface/InterfaceUApi.o

Interface/InterfaceCli.o:Interface/InterfaceCli.cpp
	${CC} ${CFLAGS} -c Interface/InterfaceCli.cpp -o Interface/InterfaceCli.o

vrf/vrf_cli.o:vrf/vrf_cli.cpp
	${CC} ${CFLAGS} -c vrf/vrf_cli.cpp -o vrf/vrf_cli.o 
vrf/vrf.o:vrf/vrf.cpp
	${CC} ${CFLAGS} -c vrf/vrf.cpp -o vrf/vrf.o 

#postgresLib files
PostgresLibpq/postgresLib.o:PostgresLibpq/postgresLib.cpp
	${CC} ${CFLAGS} -c PostgresLibpq/postgresLib.cpp -o PostgresLibpq/postgresLib.o

#ipv6 files 
Layer3/ipv6/ipv6cli.o:Layer3/ipv6/ipv6cli.cpp
	${CC} ${CFLAGS} -c Layer3/ipv6/ipv6cli.cpp -o Layer3/ipv6/ipv6cli.o
Layer3/ipv6/v6nexthop.o:Layer3/ipv6/v6nexthop.cpp
	${CC} ${CFLAGS} -c Layer3/ipv6/v6nexthop.cpp -o Layer3/ipv6/v6nexthop.o
Layer3/ipv6/ipv6_utils.o:Layer3/ipv6/ipv6_utils.cpp
	${CC} ${CFLAGS} -c Layer3/ipv6/ipv6_utils.cpp -o Layer3/ipv6/ipv6_utils.o
Layer3/ipv6/ipv6_fwd.o:Layer3/ipv6/ipv6_fwd.cpp
	${CC} ${CFLAGS} -c Layer3/ipv6/ipv6_fwd.cpp -o Layer3/ipv6/ipv6_fwd.o

Linux/LinuxInterface.o:Linux/LinuxInterface.cpp
	${CC} ${CFLAGS} -c Linux/LinuxInterface.cpp -o Linux/LinuxInterface.o

#RTM files
 RTM/rtm_nb_integ.o: RTM/rtm_nb_integ.cpp 
	${CC} ${CFLAGS} -c RTM/rtm_nb_integ.cpp -o RTM/rtm_nb_integ.o

#SR-MPLS files
Layer3/SegmentRouting/SR-MPLS/srgb.o:Layer3/SegmentRouting/SR-MPLS/srgb.cpp
	${CC} ${CFLAGS} -c Layer3/SegmentRouting/SR-MPLS/srgb.cpp -o Layer3/SegmentRouting/SR-MPLS/srgb.o

CLIBuilder/clibuilder.a:
	(cd CLIBuilder; make)
LinuxMemoryManager/libmm.a:
	(cd LinuxMemoryManager; make)
FSMImplementation/libfsm.a:
	(cd FSMImplementation; make)
FireWall/libasa.a:
	(cd FireWall; make)
${ISIS_LIB}:
	(cd Layer3/isis; make)
${SRV6_LIB}:
	(cd Layer3/SegmentRouting/SRv6; make)
${LFA_LIB}:
	(cd Layer3/LFA; make)
RTM/librtm.a:
	(cd RTM; make)
FIB/libfib.a:
	(cd FIB; make)
datapath/libdp.a:
	(cd datapath; make)

clean:
	rm -f *.o
	rm -f gluethread/glthread.o
	rm -f Tree/avl.o
	rm -f mtrie/*.o
	rm -f *exe
	rm -f ted/*.o
	rm -f Layer2/*.o
	rm -f Layer2/vxlan/cp/*.o
	rm -f Layer2/vxlan/dp/*.o
	rm -f Layer3/*.o
	rm -f Layer3/rt_table/*.o
	rm -f Layer4/*.o
	rm -f Layer5/*.o
	(cd Layer3/isis; make clean)
	(cd Layer3/SegmentRouting/SRv6; make clean)
	(cd Layer3/LFA; make clean)
	rm -f libtimer/*.o
	rm -f EventDispatcher/*.o
	rm -f BitOp/*.o
	rm -f stack/*.o
	rm -f hashmap/*.o
	rm -f packet-tracer/*.o
	rm -f prefix-list/*.o
	rm -f Threads/*.o
	(cd c-hashtable; make clean)
	rm -f Layer3/gre-tunneling/*.o
	rm -f Interface/*.o
	rm -f postgresLib/*.o
	rm -f Tracer/*.o
	rm -f common/*.o
	rm -f dpdk/layer3/*.o
	rm -f dpdk/layer2/*.o
	rm -f Layer3/ipv6/*.o
	rm -f Layer3/ipv6/SRv6/*.o
	rm -f Linux/*.o
	rm -f vrf/*.o
	rm -f Layer3/SegmentRouting/SR-MPLS/*.o
	
all:
	make
	
cleanall:
	make clean
	(cd CLIBuilder; make clean)
	(cd LinuxMemoryManager; make clean)
	(cd FSMImplementation; make clean)
	(cd FireWall; make clean)
	(cd RTM; make clean)
	(cd FIB; make clean)
	(cd datapath; make clean)
