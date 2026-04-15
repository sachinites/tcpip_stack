export CC=g++
#SANITIZER_FLAGS=-fsanitize=address,undefined
DPDK_FLAGS=-mssse3
SANITIZER_FLAGS=
export CFLAGS=-g -Wcast-align -fpermissive ${DPDK_FLAGS} -Wall -Wextra -Wmissing-prototypes -Wold-style-definition -Wold-style-declaration -gdwarf-2 -g3 -Wignored-qualifiers -g ${SANITIZER_FLAGS}
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

DPDK=-I$HOME/OpenSrc-Codes/dpdk/build/include \
	 -L$HOME/OpenSrc-Codes/dpdk/build/lib \
	 -lrte_eal -lrte_mbuf -lrte_ring -lrte_mempool -lrte_ethdev \
	 -lpthread -ldl -lnuma -lm

LIBS= ${ISIS_LIB_PATH} \
			${SRV6_LIB_PATH} \
			${LFA_LIB_PATH} \
			-LCLIBuilder -lclibuilder \
			-LFireWall -lasa \
			-Ldatapath -ldp \
			-Llibs -lstd \
			-LRTM -lrtm \
			-lpthread \
   		    -lrt \
			-lfl \
			-lm \
			-lncurses \

OBJS=router_init.o   \
		  cli_interface.o \
		  topologies.o	   \
		  net.o			   \
		  comm.o		   \
		  router.o \
		  Layer2/layer2.o  \
		  Layer2/transport_svc.o \
		  Layer2/vxlan/cp/vlan_vni_mapping.o \
		  Layer2/vxlan/cp/vxlan_cli.o \
		  Layer3/layer3.o  \
		  Layer3/gre-tunneling/grecli.o \
		  Layer3/gre-tunneling/gre.o \
		  Layer3/netfilter.o \
		  Layer3/ipv6/ipv6cli.o \
		  Layer4/layer4.o  \
		  Layer4/udp.o  \
		  Layer5/layer5.o  \
		  nwcli.o		   \
		  utils.o		   \
		  cp_ipc.o \
		  tcp_stack_init.o	\
		  tcp_ip_trace.o	\
 		  tcpip_notif.o \
		  tcp_ip_default_traps.o \
		  ted/ted.o \
		  pfxlst-cli.o \
		  Interface/Interface.o \
		  Interface/InterfaceUApi.o \
		  Interface/InterfaceCli.o \
		  dpal/cp2dp.o \
		  lmm_reg.o \
		  Linux/LinuxInterface.o \
		  RTM/rtm_nb_integ.o \
		  vrf/vrf_cli.cpp \
		  vrf/vrf.cpp \
		  Layer3/SegmentRouting/SR-MPLS/srgb.o \
		  ips_pub_sub_init.o \
		  
lmm_reg.o:lmm_reg.c
	${CC} ${CFLAGS} -c -I LinuxMemoryManager lmm_reg.c -o lmm_reg.o

Layer2/vxlan/cp/vlan_vni_mapping.o:Layer2/vxlan/cp/vlan_vni_mapping.c
	${CC} ${CFLAGS} -c -I Layer2/vxlan Layer2/vxlan/cp/vlan_vni_mapping.c -o Layer2/vxlan/cp/vlan_vni_mapping.o

Layer2/vxlan/cp/vxlan_cli.o:Layer2/vxlan/cp/vxlan_cli.c 
	${CC} ${CFLAGS} -c -I . Layer2/vxlan/cp/vxlan_cli.c -o Layer2/vxlan/cp/vxlan_cli.o

ted/ted.o:ted/ted.c
	${CC} ${CFLAGS} -c -I . ted/ted.c -o ted/ted.o

cp_ipc.o:cp_ipc.cpp
	${CC} ${CFLAGS} -c -I . cp_ipc.cpp -o cp_ipc.o

ips_pub_sub_init.o:ips_pub_sub_init.c
	${CC} ${CFLAGS} -c -I . ips_pub_sub_init.c -o ips_pub_sub_init.o

pfxlst-cli.o:pfxlst-cli.c
	${CC} ${CFLAGS} -c -I . pfxlst-cli.c -o pfxlst-cli.o

tcp_ip_default_traps.o:tcp_ip_default_traps.c
	${CC} ${CFLAGS} -c -I . tcp_ip_default_traps.c -o tcp_ip_default_traps.o

pkt_gen.exe:pkt_gen.o utils.o
	${CC} ${CFLAGS} -I tcp_public.h pkt_gen.o utils.o -o pkt_gen.exe
	@echo "pkt_gen.exe Build Finished"
	
pkt_gen.o:pkt_gen.c
	${CC} ${CFLAGS} -c pkt_gen.c -o pkt_gen.o

tcpstack.exe:main.o ${OBJS} ${ISIS_LIB} ${SRV6_LIB} ${LFA_LIB} CLIBuilder/clibuilder.a FireWall/libasa.a RTM/librtm.a datapath/libdp.a libs/libstd.a
	${CC} ${CFLAGS} main.o ${OBJS}  ${LIBS} ${DPDK} -o tcpstack.exe
	@echo "tcpstack.exe Build Finished"

tcpip_notif.o:tcpip_notif.c
	${CC} ${CFLAGS} -c -I gluethread -I . tcpip_notif.c -o tcpip_notif.o

main.o:main.c
	${CC} ${CFLAGS} -c main.c -o main.o

tcp_stack_init.o:tcp_stack_init.c
	${CC} ${CFLAGS} -c tcp_stack_init.c -o tcp_stack_init.o

router_init.o:router_init.c
	${CC} ${CFLAGS} -c -I . router_init.c -o router_init.o

dpal/cp2dp.o:dpal/cp2dp.cpp
	${CC} ${CFLAGS} -c -I . dpal/cp2dp.cpp -o dpal/cp2dp.o

cli_interface.o:cli_interface.c
	${CC} ${CFLAGS} -c -I . cli_interface.c -o cli_interface.o

topologies.o:topologies.c
	${CC} ${CFLAGS} -c -I . topologies.c -o topologies.o

net.o:net.c
	${CC} ${CFLAGS} -c -I . net.c -o net.o

comm.o:comm.c
	${CC} ${CFLAGS} -c -I . comm.c -o comm.o

router.o:router.cpp
	${CC} ${CFLAGS} -c -I . router.cpp -o router.o

tcp_ip_trace.o:tcp_ip_trace.c
	${CC} ${CFLAGS} -c -I . tcp_ip_trace.c -o tcp_ip_trace.o

Layer2/layer2.o:Layer2/layer2.c
	${CC} ${CFLAGS} -c -I . Layer2/layer2.c -o Layer2/layer2.o

Layer2/transport_svc.o:Layer2/transport_svc.cpp 
	${CC} ${CFLAGS} -c -I . Layer2/transport_svc.cpp -o Layer2/transport_svc.o

Layer3/layer3.o:Layer3/layer3.c
	${CC} ${CFLAGS} -c -I . Layer3/layer3.c -o Layer3/layer3.o

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

#ipv6 files 
Layer3/ipv6/ipv6cli.o:Layer3/ipv6/ipv6cli.cpp
	${CC} ${CFLAGS} -c Layer3/ipv6/ipv6cli.cpp -o Layer3/ipv6/ipv6cli.o

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
datapath/libdp.a:
	(cd datapath; make)
libs/libstd.a:
	(cd libs; make)
clean:
	rm -f *.o
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
	rm -f Layer3/gre-tunneling/*.o
	rm -f Interface/*.o
	rm -f dpdk/layer3/*.o
	rm -f dpdk/layer2/*.o
	rm -f Layer3/ipv6/*.o
	rm -f Layer3/ipv6/SRv6/*.o
	rm -f Linux/*.o
	rm -f vrf/*.o
	rm -f Layer3/SegmentRouting/SR-MPLS/*.o
	rm -f dpal/*.o
	
all:
	make
	
cleanall:
	make clean
	(cd CLIBuilder; make clean)
	(cd FireWall; make clean)
	(cd RTM; make clean)
	(cd datapath; make clean)
	(cd libs; make clean)
