CC=g++
CFLAGS=-g -gdwarf-2 -g3 -Wignored-qualifiers
TARGET:libmm.a
OUTFILES=libmm.a
EXTERNAL_LIBS=-lpthread
OBJS=../gluethread/glthread.o mm.o
mm.o:mm.c
	${CC} ${CFLAGS} -c mm.c -o mm.o
libmm.a:${OBJ}
	ar rs libmm.a ${OBJ}
clean:
	rm -f ${OUTFILES}
	rm -f *.o
