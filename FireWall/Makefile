CC=gcc
CFLAGS=-g
TARGET:libasa.a
LIB=libasa.a
OBJS=acl/acl.o
${LIB}:acl/acl.o ipsec/sadb.o
	ar rs ${LIB} ${OBJ}
acl/acl.o:acl/acl.c
	${CC} ${CFLAGS} -c -I . -I ../ acl/acl.c -o acl/acl.o
ipsec/sadb.o:ipsec/sadb.c
	${CC} ${CFLAGS} -c -I . -I ../ ipsec/sadb.c -o ipsec/sadb.o
clean:
	rm -f acl/*.o
	rm -f ipsec/*.o
	rm -f ${LIB}
