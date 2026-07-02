TARGET_LIB=liblfa.a

# Inherit CFLAGS/SANITIZER_FLAGS from top-level make when invoked via $(MAKE) -C.
CFLAGS ?= -g -Wall -Wextra -fpermissive $(SANITIZER_FLAGS) -MMD -MP

TARGET:${TARGET_LIB}

OBJS=cp/lfa.o \
			cp/lfa_cli.o \
			cp/lfa_isis.o \

# Control Plane
cp/lfa.o:cp/lfa.cpp
	${CC} ${CFLAGS} -c -fPIC -I . cp/lfa.cpp -o cp/lfa.o

cp/lfa_cli.o:cp/lfa_cli.cpp
	${CC} ${CFLAGS} -c -fPIC -I . cp/lfa_cli.cpp -o cp/lfa_cli.o

cp/lfa_isis.o:cp/lfa_isis.cpp
	${CC} ${CFLAGS} -c -fPIC -I . cp/lfa_isis.cpp -o cp/lfa_isis.o

${TARGET_LIB}:${OBJS}
	ar rs ${TARGET_LIB} ${OBJS}
	@echo LFA Library ${TARGET_LIB} compiled successfully

clean:
	rm -rf cp/*.o cp/*.d
	rm -rf *.a

-include $(OBJS:.o=.d)
