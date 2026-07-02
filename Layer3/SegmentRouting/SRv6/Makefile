CC=g++

# Inherit CFLAGS/SANITIZER_FLAGS from top-level make when invoked via $(MAKE) -C.
CFLAGS ?= -g -Wall -Wextra -fpermissive $(SANITIZER_FLAGS) -MMD -MP

TARGET_LIB=libsrv6.a

TARGET:${TARGET_LIB}

OBJS=cp/srv6_cli.o \
			cp/srv6_api.o \
			cp/srv6_rtm.o \
			cp/srv6_show.o \
			cp/srv6_sid_pool.o \
			common/srv6_const.o \

# Control Plane

cp/srv6_cli.o:cp/srv6_cli.cpp
	${CC} ${CFLAGS} -c -fPIC -I ../../../ cp/srv6_cli.cpp -o cp/srv6_cli.o

cp/srv6_api.o:cp/srv6_api.cpp
	${CC} ${CFLAGS} -c -fPIC -I ../../../ cp/srv6_api.cpp -o cp/srv6_api.o

cp/srv6_rtm.o:cp/srv6_rtm.cpp
	${CC} ${CFLAGS} -c -fPIC -I ../../../ cp/srv6_rtm.cpp -o cp/srv6_rtm.o

cp/srv6_sid_pool.o:cp/srv6_sid_pool.cpp
	${CC} ${CFLAGS} -c -fPIC -I ../../../ cp/srv6_sid_pool.cpp -o cp/srv6_sid_pool.o

cp/srv6_show.o:cp/srv6_show.cpp
	${CC} ${CFLAGS} -c -fPIC -I ../../../ cp/srv6_show.cpp -o cp/srv6_show.o

common/srv6_const.o:common/srv6_const.cpp
	${CC} ${CFLAGS} -c -fPIC -I ../../../ common/srv6_const.cpp -o common/srv6_const.o

${TARGET_LIB}:${OBJS}
	ar rs ${TARGET_LIB} ${OBJS}
	@echo SRv6 Library ${TARGET_LIB} compiled successfully

clean:
	rm -rf *.o *.d
	rm -rf *.a
	rm -rf cp/*.o cp/*.d
	rm -rf common/*.o common/*.d

-include $(OBJS:.o=.d)
