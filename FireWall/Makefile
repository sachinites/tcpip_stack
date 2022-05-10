CC=gcc
CFLAGS=-g
TARGET:libasa.a
LIB=libasa.a
OBJS=acl/acl_cli.o acl/acldb.o mtrie/mtrie.o 
${LIB}:acl/acl_cli.o acl/acldb.o mtrie/mtrie.o
	ar rs ${LIB} ${OBJS}
acl/acl_cli.o:acl/acl_cli.c
	${CC} ${CFLAGS} -c -I . -I ../ acl/acl_cli.c -o acl/acl_cli.o
acl/acldb.o:acl/acldb.c
	${CC} ${CFLAGS} -c -I . -I ../ acl/acldb.c -o acl/acldb.o
mtrie/mtrie.o:mtrie/mtrie.c
	${CC} ${CFLAGS} -c -I . -I ../ mtrie/mtrie.c -o mtrie/mtrie.o
clean:
	rm -f acl/acl*.o
	rm -f ${LIB}
