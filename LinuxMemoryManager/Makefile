CC=gcc
CFLAGS=-g
TARGET:testapp.exe libmm.a
OUTFILES=testapp.exe libmm.a
EXTERNAL_LIBS=
OBJS=../gluethread/glthread.o mm.o

testapp.exe:testapp.o ${OBJS}
	${CC} ${CFLAGS} testapp.o ${OBJS} -o testapp.exe ${EXTERNAL_LIBS}
testapp.o:testapp.c
	${CC} ${CFLAGS} -c testapp.c -o testapp.o
mm.o:mm.c
	${CC} ${CFLAGS} -c mm.c -o mm.o
libmm.a:${OBJ}
	ar rs libmm.a ${OBJ}
clean:
	rm -f ${OUTFILES}
	rm -f *.o
