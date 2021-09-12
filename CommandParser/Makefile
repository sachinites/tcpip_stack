CC=gcc
CFLAGS=-g -Wall
INCLUDES=-I .
CLILIB=libcli.a
TARGET:${CLILIB}
OBJ=cmd_hier.o parser.o serialize.o string_util.o clistd.o clicbext.o ../EventDispatcher/event_dispatcher.o ../gluethread/glthread.o ut/utinfra/ut_parser.o
cmd_hier.o:cmd_hier.c
	@echo "Building cmd_hier.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} cmd_hier.c -o cmd_hier.o
parser.o:parser.c
	@echo "Building parser.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} parser.c -o parser.o
serialize.o:serialize.c
	@echo "Building serialize.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} serialize.c -o serialize.o
string_util.o:string_util.c
	@echo "Building string_util.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} string_util.c -o string_util.o
clistd.o:clistd.c
	@echo "Building clistd.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} clistd.c -o clistd.o
clicbext.o:clicbext.c
	@echo "Building clicbext.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} clicbext.c -o clicbext.o
testapp.o:testapp.c
	@echo "Building testapp.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} testapp.c -o testapp.o
ut/utinfra/ut_parser.o:ut/utinfra/ut_parser.c
	@echo "Building ut/utinfra/ut_parser.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} ut/utinfra/ut_parser.c -o ut/utinfra/ut_parser.o
${CLILIB}: ${OBJ}
	@echo "Building Library ${CLILIB}"
	ar rs ${CLILIB} ${OBJ}
clean:
	rm -f *.o
	rm -f ut/utinfra/*.o
	rm -f ${CLILIB}
	rm -f CMD_HIST_RECORD_FILE.txt
install:
	cp ${CLILIB} /usr/local/lib/
	cp libcli.h /usr/include/
	cp cmdtlv.h /usr/include/
uninstall:
	rm -f /usr/local/lib/${CLILIB}
	rm -f /usr/include/libcli.h
	rm -f /usr/include/cmdtlv.h
