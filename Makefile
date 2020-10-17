CC=gcc
CFLAGS=-g
TARGET:tcpstack.exe CommandParser/libcli.a pkt_gen.exe
LIBS=-lpthread -L ./CommandParser -lcli
OBJS=gluethread/glthread.o \
		  Tree/avl.o	   \
		  graph.o 		   \
		  topologies.o	   \
		  net.o			   \
		  comm.o		   \
		  Layer2/layer2.o  \
		  Layer3/layer3.o  \
		  Layer4/layer4.o  \
		  Layer5/layer5.o  \
		  nwcli.o		   \
		  utils.o		   \
		  Layer2/l2switch.o \
          WheelTimer/WheelTimer.o   \
          Layer5/nbrship_mgmt/nbrship_mgmt.o \
		  Layer5/ddcp/ddcp.o \
		  Layer5/spf_algo/spf.o \
		  tcp_stack_init.o	\
		  tcp_ip_trace.o	\
 		  tcpip_notif.o \
		  notif.o

pkt_gen.exe:pkt_gen.o utils.o
	${CC} ${CFLAGS} -I tcp_public.h pkt_gen.o utils.o -o pkt_gen.exe

pkt_gen.o:pkt_gen.c
	${CC} ${CFLAGS} -c pkt_gen.c -o pkt_gen.o

tcpstack.exe:testapp.o ${OBJS} CommandParser/libcli.a
	${CC} ${CFLAGS} testapp.o ${OBJS} -o tcpstack.exe ${LIBS}

notif.o:notif.c
	${CC} ${CFLAGS} -c -I gluethread -I . notif.c -o notif.o

tcpip_notif.o:tcpip_notif.c
	${CC} ${CFLAGS} -c -I gluethread -I . tcpip_notif.c -o tcpip_notif.o

testapp.o:testapp.c
	${CC} ${CFLAGS} -c testapp.c -o testapp.o

gluethread/glthread.o:gluethread/glthread.c
	${CC} ${CFLAGS} -c -I gluethread gluethread/glthread.c -o gluethread/glthread.o

Tree/avl.o:Tree/avl.c
	${CC} ${CFLAGS} -c -I Tree Tree/avl.c -o Tree/avl.o

WheelTimer/WheelTimer.o:WheelTimer/WheelTimer.c
	${CC} ${CFLAGS} -c -I gluethread -I WheelTimer WheelTimer/WheelTimer.c -o WheelTimer/WheelTimer.o

tcp_stack_init.o:tcp_stack_init.c
	${CC} ${CFLAGS} -c tcp_stack_init.c -o tcp_stack_init.o

Layer5/nbrship_mgmt/nbrship_mgmt.o:Layer5/nbrship_mgmt/nbrship_mgmt.c
	${CC} ${CFLAGS} -c -I . Layer5/nbrship_mgmt/nbrship_mgmt.c -o Layer5/nbrship_mgmt/nbrship_mgmt.o

graph.o:graph.c
	${CC} ${CFLAGS} -c -I . graph.c -o graph.o

topologies.o:topologies.c
	${CC} ${CFLAGS} -c -I . topologies.c -o topologies.o

net.o:net.c
	${CC} ${CFLAGS} -c -I . net.c -o net.o

comm.o:comm.c
	${CC} ${CFLAGS} -c -I . comm.c -o comm.o

tcp_ip_trace.o:tcp_ip_trace.c
	${CC} ${CFLAGS} -c -I . tcp_ip_trace.c -o tcp_ip_trace.o

Layer2/layer2.o:Layer2/layer2.c
	${CC} ${CFLAGS} -c -I . Layer2/layer2.c -o Layer2/layer2.o

Layer2/l2switch.o:Layer2/l2switch.c
	${CC} ${CFLAGS} -c -I . Layer2/l2switch.c -o Layer2/l2switch.o

Layer3/layer3.o:Layer3/layer3.c
	${CC} ${CFLAGS} -c -I . Layer3/layer3.c -o Layer3/layer3.o

Layer5/spf_algo/spf.o:Layer5/spf_algo/spf.c
	${CC} ${CFLAGS} -c -I . Layer5/spf_algo/spf.c -o Layer5/spf_algo/spf.o

Layer4/layer4.o:Layer4/layer4.c
	${CC} ${CFLAGS} -c -I . Layer4/layer4.c -o Layer4/layer4.o
	
Layer5/layer5.o:Layer5/layer5.c
	${CC} ${CFLAGS} -c -I . Layer5/layer5.c -o Layer5/layer5.o

nwcli.o:nwcli.c
	${CC} ${CFLAGS} -c -I . nwcli.c  -o nwcli.o

utils.o:utils.c
	${CC} ${CFLAGS} -c -I . utils.c -o utils.o

Layer5/ddcp/ddcp.o:Layer5/ddcp/ddcp.c
	${CC} ${CFLAGS} -c -I . -I Layer5/ddcp/ Layer5/ddcp/ddcp.c -o Layer5/ddcp/ddcp.o

CommandParser/libcli.a:
	(cd CommandParser; make)
clean:
	rm -f *.o
	rm -f gluethread/glthread.o
	rm -f Tree/avl.o
	rm -f *exe
	rm -f Layer2/*.o
	rm -f Layer3/*.o
	rm -f Layer4/*.o
	rm -f Layer5/*.o
	rm -f Layer5/ddcp/*.o
	rm -f Layer5/spf_algo/*.o
	rm -f WheelTimer/WheelTimer.o
	rm -f Layer5/nbrship_mgmt/*.o
all:
	make
	(cd CommandParser; make)

cleanall:
	make clean
	(cd CommandParser; make clean)
	rm -f WheelTimer/WheelTimer.o
