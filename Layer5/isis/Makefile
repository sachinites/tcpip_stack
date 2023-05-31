CC=g++
CFLAGS=-g -fpermissive -Wall -Wextra -Wmissing-prototypes -Wold-style-definition -Wold-style-declaration -gdwarf-2 -g3
STATIC_LIBNAME=libisis.a
TARGET:${STATIC_LIBNAME}
ISIS_OBJS=isis_adjacency.o \
		  isis_cli.o \
		  isis_rtr.o \
		  isis_intf.o \
		  isis_pkt.o \
		  isis_events.o \
		  isis_flood.o \
		  isis_lspdb.o \
		  isis_spf.o \
		  isis_mem_init.o \
		  isis_intf_group.o \
		  isis_layer2map.o \
		  isis_ted.o \
		  isis_policy.o \
		  isis_tlv_struct.o \
		  isis_advt.o \
		  isis_dis.o \
		  isis_utils.o \

isis_adjacency.o:isis_adjacency.c
	${CC} ${CFLAGS} -c -fPIC -I . isis_adjacency.c -o isis_adjacency.o

isis_cli.o:isis_cli.c
	${CC} ${CFLAGS} -c -fPIC -I . isis_cli.c -o isis_cli.o

isis_rtr.o:isis_rtr.c
	${CC} ${CFLAGS} -c -fPIC -I . isis_rtr.c -o isis_rtr.o

isis_intf.o:isis_intf.c
	${CC} ${CFLAGS} -c -fPIC  -I . isis_intf.c -o isis_intf.o

isis_pkt.o:isis_pkt.c
	${CC} ${CFLAGS} -c -fPIC  -I . isis_pkt.c -o isis_pkt.o

isis_flood.o:isis_flood.c
	${CC} ${CFLAGS} -c -fPIC  -I . isis_flood.c -o isis_flood.o

isis_events.o:isis_events.c
	${CC} ${CFLAGS} -c -fPIC  -I . isis_events.c -o isis_events.o

isis_lspdb.o:isis_lspdb.c
	${CC} ${CFLAGS} -c -fPIC  -I . isis_lspdb.c -o isis_lspdb.o

isis_spf.o:isis_spf.c
	${CC} ${CFLAGS} -c -fPIC  -I . isis_spf.c -o isis_spf.o

isis_mem_init.o:isis_mem_init.c
	${CC} ${CFLAGS} -c -fPIC  -I . isis_mem_init.c -o isis_mem_init.o

isis_intf_group.o:isis_intf_group.c
	${CC} ${CFLAGS} -c -fPIC  -I . isis_intf_group.c -o isis_intf_group.o

isis_layer2map.o:isis_layer2map.c
	${CC} ${CFLAGS} -c -fPIC  -I . isis_layer2map.c -o isis_layer2map.o

isis_ted.o:isis_ted.c
	${CC} ${CFLAGS} -c -fPIC  -I . isis_ted.c -o isis_ted.o

isis_policy.o:isis_policy.c
	${CC} ${CFLAGS} -c -fPIC  -I . isis_policy.c -o isis_policy.o

isis_tlv_struct.o:isis_tlv_struct.c
	${CC} ${CFLAGS} -c -fPIC  -I . isis_tlv_struct.c -o isis_tlv_struct.o

isis_advt.o:isis_advt.cpp
	${CC} ${CFLAGS} -c -fPIC  -I . isis_advt.cpp -o isis_advt.o

isis_dis.o:isis_dis.cpp
	${CC} ${CFLAGS} -c -fPIC  -I . isis_dis.cpp -o isis_dis.o

isis_utils.o:isis_utils.cpp
	${CC} ${CFLAGS} -c -fPIC  -I . isis_utils.cpp -o isis_utils.o

${STATIC_LIBNAME}:${ISIS_OBJS}
	ar rs ${STATIC_LIBNAME} ${ISIS_OBJS}
	@echo ISIS Library ${STATIC_LIBNAME} compiled successfully

clean:
	rm -f *.o 
	rm -f *.a
