CC=g++
CFLAGS=-g -fpermissive -Wall -gdwarf-2 -g3 -Wignored-qualifiers
INCLUDES=-I .
CLILIB=libclibuilder.a
TARGET:${CLILIB}
OBJ=KeyProcessor/KeyProcessor.o \
		 string_util.o \
		 ../stack/stack.o \
		 CmdTree/CmdTree.o \
		 CmdTree/clistd.o \
		 CmdTree/CmdTreeCursor.o \
		 ../gluethread/glthread.o \
		 Filters/filters.o \
		 utinfra/ut_parser.o \
		 
KeyProcessor/KeyProcessor.o:KeyProcessor/KeyProcessor.cpp
	@echo "Building KeyProcessor/KeyProcessor.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} KeyProcessor/KeyProcessor.cpp -o KeyProcessor/KeyProcessor.o

../stack/stack.o:../stack/stack.c
	@echo "Building ../stack/stack.o"
	@ ${CC} ${CFLAGS} -c -I ../stack ../stack/stack.c -o ../stack/stack.o

../gluethread/glthread.o:../gluethread/glthread.c
	@echo "Building ../gluethread/glthread.o"
	@ ${CC} ${CFLAGS} -c -I ../gluethread ../gluethread/glthread.c -o ../gluethread/glthread.o

string_util.o:string_util.c
	@echo "Building string_util.o"
	@ ${CC} ${CFLAGS} -c -I . string_util.c -o string_util.o

CmdTree/clistd.o:CmdTree/clistd.cpp
	@echo "Building CmdTree/clistd.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} CmdTree/clistd.cpp -o CmdTree/clistd.o

CmdTree/CmdTreeCursor.o:CmdTree/CmdTreeCursor.cpp
	@echo "Building CmdTree/CmdTreeCursor.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} CmdTree/CmdTreeCursor.cpp -o CmdTree/CmdTreeCursor.o

CmdTree/CmdTree.o:CmdTree/CmdTree.cpp
	@echo "Building CmdTree/CmdTree.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} CmdTree/CmdTree.cpp -o CmdTree/CmdTree.o

Filters/filters.o:Filters/filters.cpp
	@echo "Building Filters/filters.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} Filters/filters.cpp -o Filters/filters.o

utinfra/ut_parser.o:utinfra/ut_parser.cpp
	@echo "Building utinfra/ut_parser.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} utinfra/ut_parser.cpp -o utinfra/ut_parser.o

testapp.o:testapp.c
	@echo "Building testapp.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} testapp.c -o testapp.o

${CLILIB}: ${OBJ}
	@echo "Building Library ${CLILIB}"
	ar rs ${CLILIB} ${OBJ}

acl_cli.o:acl_cli.c
	@echo "Building acl_cli.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} acl_cli.c -o acl_cli.o

clean:
	rm -f *.exe
	rm -f *.o
	rm -f CmdTree/*.o 
	rm -f KeyProcessor/*.o
	rm -f Filters/*.o
	rm -f utinfra/*.o
	rm -f ${CLILIB}
