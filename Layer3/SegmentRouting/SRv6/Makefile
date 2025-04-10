TARGET_LIB=libsrv6.a

TARGET:${TARGET_LIB}

OBJS=cp/srv6_cli.o \
			cp/srv6_api.o \
			cp/srv6_mem_init.o \
			cp/srv6_show.o \
			cp/srv6_sid_pool.o \
			common/srv6_const.o \
			dp/srv6-endpoint.o \
			dp/srv6-end-behavior.o \

# Control Plane

cp/srv6_cli.o:cp/srv6_cli.cpp
	${CC} ${CFLAGS} -c -fPIC -I ../../../ cp/srv6_cli.cpp -o cp/srv6_cli.o

cp/srv6_api.o:cp/srv6_api.cpp
	${CC} ${CFLAGS} -c -fPIC -I ../../../ cp/srv6_api.cpp -o cp/srv6_api.o

cp/srv6_mem_init.o:cp/srv6_mem_init.cpp
	${CC} ${CFLAGS} -c -fPIC -I ../../../ cp/srv6_mem_init.cpp -o cp/srv6_mem_init.o

cp/srv6_sid_pool.o:cp/srv6_sid_pool.cpp
	${CC} ${CFLAGS} -c -fPIC -I ../../../ cp/srv6_sid_pool.cpp -o cp/srv6_sid_pool.o

cp/srv6_show.o:cp/srv6_show.cpp
	${CC} ${CFLAGS} -c -fPIC -I ../../../ cp/srv6_show.cpp -o cp/srv6_show.o

common/srv6_const.o:common/srv6_const.cpp
	${CC} ${CFLAGS} -c -fPIC -I ../../../ common/srv6_const.cpp -o common/srv6_const.o

# Data plane
dp/srv6-endpoint.o:dp/srv6-endpoint.cpp
	${CC} ${CFLAGS} -c -fPIC -I ../../../ dp/srv6-endpoint.cpp -o dp/srv6-endpoint.o

dp/srv6-end-behavior.o:dp/srv6-end-behavior.cpp
	${CC} ${CFLAGS} -c -fPIC -I ../../../ dp/srv6-end-behavior.cpp -o dp/srv6-end-behavior.o

${TARGET_LIB}:${OBJS}
	ar rs ${TARGET_LIB} ${OBJS}
	@echo SRv6 Library ${TARGET_LIB} compiled successfully

clean:
	rm -rf *.o 
	rm -rf *.a
	rm -rf cp/*.o 
	rm -rf dp/*.o 
	rm -rf common/*.o
	
