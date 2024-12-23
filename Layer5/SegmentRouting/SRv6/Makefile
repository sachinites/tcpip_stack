CC=g++
SANITIZER_FLAGS=-fsanitize=address,undefined
CFLAGS=-g -Wcast-align -fpermissive -Wall -Wextra -Wmissing-prototypes -Wold-style-definition -Wold-style-declaration -gdwarf-2 -g3 -Wignored-qualifiers -g ${SANITIZER_FLAGS}

TARGET_LIB=libsrv6.a

TARGET:${TARGET_LIB}

OBJS=srv6_rtr.o \

srv6_rtr.o:srv6_rtr.cpp
	${CC} ${CFLAGS} -c -fPIC -I . srv6_rtr.cpp -o srv6_rtr.o

${TARGET_LIB}:${OBJS}
	ar rs ${TARGET_LIB} ${OBJS}
	@echo SRv6 Library ${TARGET_LIB} compiled successfully

clean:
	rm -rf *.o 
	rm -rf *.a