CC=g++
CFLAGS=-g -fpermissive -gdwarf-2 -g3 -Wignored-qualifiers
TARGET:libasa.a
LIB=libasa.a
OBJS=acl/acl_cli.o \
			acl/acldb.o \
			object_network/obj_nw_cli.o \
			object_network/objnw.o \
			Connection/conn.o \
			object_network/obj_grp_cli.o \
			object_network/object_group.o \
			object_network/object_group_update.o \
			../Interface/InterfaceCli.o \

${LIB}:${OBJS}
	ar rs ${LIB} ${OBJS}

acl/acl_cli.o:acl/acl_cli.c
	${CC} ${CFLAGS} -c -I . -I ../ acl/acl_cli.c -o acl/acl_cli.o
acl/acldb.o:acl/acldb.c
	${CC} ${CFLAGS} -c -I . -I ../ acl/acldb.c -o acl/acldb.o

object_network/obj_nw_cli.o:object_network/obj_nw_cli.c
	${CC} ${CFLAGS} -c -I . -I ../../ object_network/obj_nw_cli.c -o object_network/obj_nw_cli.o
object_network/objnw.o:object_network/objnw.c
	${CC} ${CFLAGS} -c -I . -I ../../ object_network/objnw.c -o object_network/objnw.o	

object_network/obj_grp_cli.o:object_network/obj_grp_cli.c
	${CC} ${CFLAGS} -c -I . -I ../../ object_network/obj_grp_cli.c -o object_network/obj_grp_cli.o
object_network/object_group.o:object_network/object_group.c
	${CC} ${CFLAGS} -c -I . -I ../../ object_network/object_group.c -o object_network/object_group.o
object_network/object_group_update.o:object_network/object_group_update.c
	${CC} ${CFLAGS} -c -I . -I ../../ object_network/object_group_update.c -o object_network/object_group_update.o	

../Interface/InterfaceCli.o:../Interface/InterfaceCli.cpp
	${CC} ${CFLAGS} -c ../Interface/InterfaceCli.cpp -o ../Interface/InterfaceCli.o

Connection/conn.o:Connection/conn.c
	${CC} ${CFLAGS} -c -I . -I ../../ Connection/conn.c -o Connection/conn.o

clean:
	rm -f acl/acl*.o
	rm -f object_network/*.o
	rm -f Connection/*.o
	rm -f ${LIB}
