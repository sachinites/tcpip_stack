CC=gcc
CFLAGS=-g
TARGET:libasa.a
LIB=libasa.a
OBJS=acl/acl.o
${LIB}:acl/acl.o
	ar rs ${LIB} ${OBJ}
acl/acl.o:acl/acl.c
	${CC} ${CFLAGS} -c -I . -I ../ acl/acl.c -o acl/acl.o
clean:
	rm -f acl/acl*.o
	rm -f ${LIB}
