CC=g++
CFLAGS=-g -fpermissive -Wall -Wextra -Wmissing-prototypes -Wold-style-definition -Wold-style-declaration -gdwarf-2 -g3 -Wignored-qualifiers
TARGET:tcpstack.exe pkt_gen.exe

# Install external dependent libs :   sudo apt-get install libpq-dev

# Proto Libs
ISIS_LIB=Layer5/isis/libisis.a
ISIS_LIB_PATH=-L Layer5/isis -lisis
# proto Libs

LIBS=-lpthread \
			-lpq \
		    -lrt \
			-lncurses \
			-lpthread \
		   -L CLIBuilder -lclibuilder \
		    -L LinuxMemoryManager -lmm \
			-L FSMImplementation -lfsm \
			-L FireWall -lasa \
			-lrt -lm -lncurses \
			${ISIS_LIB_PATH} \

OBJS=gluethread/glthread.o \
		  BitOp/bitmap.o \
		  stack/stack.o \
		  Tree/avl.o	   \
		  mtrie/mtrie.o	   \
		  graph.o 		   \
		  cli_interface.o \
		  topologies.o	   \
		  net.o			   \
		  comm.o		   \
		  Layer2/layer2.o  \
		  Layer2/transport_svc.o  \
		  Layer2/arp.o	   \
		  Layer3/layer3.o  \
		  Layer3/gre-tunneling/grecli.o \
		  Layer3/gre-tunneling/gre.o \
		  Layer3/rt_table/nexthop.o \
		  Layer3/netfilter.o \
		  Layer3/rt_notif.o	\
		  Layer4/layer4.o  \
		  Layer4/udp.o  \
		  Layer5/layer5.o  \
		  nwcli.o		   \
		  utils.o		   \
		  Layer2/l2switch.o \
          libtimer/WheelTimer.o   \
          libtimer/timerlib.o   \
		  libtimer/timedef.o \
		  Tracer/tracer.o \
		  Layer5/spf_algo/spf.o \
		  tcp_stack_init.o	\
		  pkt_block.o \
		  tcp_ip_trace.o	\
 		  tcpip_notif.o \
		  configdb.o \
		  notif.o	\
		  EventDispatcher/event_dispatcher.o \
		  tcp_ip_default_traps.o \
		  ted/ted.o \
		  LinuxMemoryManager/mm.o \
		  flow/snp_flow.o \
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
		  dpdk/layer3/dp_rtm.o \
		  #Layer2/stp/stp_state_machine.o \
		  Layer2/stp/stp_bpdu.o \
		  Layer2/stp/stp_init.o \
		  Layer2/stp/stp_vlandb.o \

Threads/refcount.o:Threads/refcount.c
	${CC} ${CFLAGS} -c Threads/refcount.c -o Threads/refcount.o

Tracer/tracer.o:Tracer/tracer.cpp
	${CC} ${CFLAGS} -I Tracer -c Tracer/tracer.cpp -o Tracer/tracer.o

ted/ted.o:ted/ted.c
	${CC} ${CFLAGS} -c -I . ted/ted.c -o ted/ted.o

flow/snp_flow.o:flow/snp_flow.c
	${CC} ${CFLAGS} -c -I . flow/snp_flow.c -o flow/snp_flow.o

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

tcpstack.exe:main.o ${OBJS} CLIBuilder/clibuilder.a LinuxMemoryManager/libmm.a FSMImplementation/libfsm.a FireWall/libasa.a ${ISIS_LIB}
	${CC} ${CFLAGS} main.o ${OBJS}  ${LIBS} -o tcpstack.exe
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

graph.o:graph.c
	${CC} ${CFLAGS} -c -I . graph.c -o graph.o

common/cp2dp.o:common/cp2dp.cpp
	${CC} ${CFLAGS} -c -I . common/cp2dp.cpp -o common/cp2dp.o

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

Layer3/layer3.o:Layer3/layer3.c
	${CC} ${CFLAGS} -c -I . Layer3/layer3.c -o Layer3/layer3.o

Layer3/rt_table/nexthop.o:Layer3/rt_table/nexthop.c
	${CC} ${CFLAGS} -c -I . Layer3/rt_table/nexthop.c -o Layer3/rt_table/nexthop.o

dpdk/layer3/dp_rtm.o:dpdk/layer3/dp_rtm.cpp
	${CC} ${CFLAGS} -c -I . dpdk/layer3/dp_rtm.cpp -o dpdk/layer3/dp_rtm.o

Layer3/rt_notif.o:Layer3/rt_notif.c
	${CC} ${CFLAGS} -c -I . Layer3/rt_notif.c -o Layer3/rt_notif.o

Layer3/netfilter.o:Layer3/netfilter.c
	${CC} ${CFLAGS} -c -I . Layer3/netfilter.c -o Layer3/netfilter.o

Layer5/spf_algo/spf.o:Layer5/spf_algo/spf.c
	${CC} ${CFLAGS} -c -I . Layer5/spf_algo/spf.c -o Layer5/spf_algo/spf.o

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

#postgresLib files
PostgresLibpq/postgresLib.o:PostgresLibpq/postgresLib.cpp
	${CC} ${CFLAGS} -c PostgresLibpq/postgresLib.cpp -o PostgresLibpq/postgresLib.o


# Protocols Specific
# STP
#Layer2/stp/stp_state_machine.o:Layer2/stp/stp_state_machine.c
#	${CC} ${CFLAGS} -c Layer2/stp/stp_state_machine.c -o Layer2/stp/stp_state_machine.o
#Layer2/stp/stp_bpdu.o:Layer2/stp/stp_bpdu.c
#	${CC} ${CFLAGS} -c Layer2/stp/stp_bpdu.c -o Layer2/stp/stp_bpdu.o
#Layer2/stp/stp_init.o:Layer2/stp/stp_init.c
#	${CC} ${CFLAGS} -c Layer2/stp/stp_init.c -o Layer2/stp/stp_init.o
#Layer2/stp/stp_vlandb.o:Layer2/stp/stp_vlandb.c
#	${CC} ${CFLAGS} -c Layer2/stp/stp_vlandb.c -o Layer2/stp/stp_vlandb.o

CLIBuilder/clibuilder.a:
	(cd CLIBuilder; make)
LinuxMemoryManager/libmm.a:
	(cd LinuxMemoryManager; make)
FSMImplementation/libfsm.a:
	(cd FSMImplementation; make)
FireWall/libasa.a:
	(cd FireWall; make)
${ISIS_LIB}:
	(cd Layer5/isis; make)

clean:
	rm -f *.o
	rm -f gluethread/glthread.o
	rm -f Tree/avl.o
	rm -f mtrie/*.o
	rm -f *exe
	rm -f ted/*.o
	rm -f flow/*.o
	rm -f Layer2/*.o
	rm -f Layer3/*.o
	rm -f Layer3/rt_table/*.o
	rm -f Layer4/*.o
	rm -f Layer5/*.o
	(cd Layer5/isis; make clean)
	rm -f Layer5/spf_algo/*.o
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
#STP
#	rm -f Layer2/stp/*.o
all:
	make
	
cleanall:
	make clean
	(cd CLIBuilder; make clean)
	(cd LinuxMemoryManager; make clean)
	(cd FSMImplementation; make clean)
	(cd FireWall; make clean)
