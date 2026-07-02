CC=g++

# Inherit CFLAGS/SANITIZER_FLAGS from top-level make when invoked via $(MAKE) -C.
CFLAGS ?= -g -Wall -Wextra -fpermissive $(SANITIZER_FLAGS) -MMD -MP

INCLUDES=-I .
CLILIB=libclibuilder.a
TARGET:${CLILIB}
OBJ=KeyProcessor/KeyProcessor.o \
		 string_util.o \
		 ../libs/stack/stack.o \
		 CmdTree/CmdTree.o \
		 CmdTree/clistd.o \
		 CmdTree/CmdTreeCursor.o \
		 ../libs/gluethread/glthread.o \
		 Filters/filters.o \
		 Filters/A_B.o \
		 utinfra/ut_parser.o \

		 
KeyProcessor/KeyProcessor.o:KeyProcessor/KeyProcessor.cpp
	@echo "Building KeyProcessor/KeyProcessor.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} KeyProcessor/KeyProcessor.cpp -o KeyProcessor/KeyProcessor.o

../libs/stack/stack.o:../libs/stack/stack.c
	@echo "Building ../libs/stack/stack.o"
	@ ${CC} ${CFLAGS} -c -I ../libs/stack ../libs/stack/stack.c -o ../libs/stack/stack.o

../libs/gluethread/glthread.o:../libs/gluethread/glthread.c
	@echo "Building ../libs/gluethread/glthread.o"
	@ ${CC} ${CFLAGS} -c -I ../libs/gluethread ../libs/gluethread/glthread.c -o ../libs/gluethread/glthread.o

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

Filters/A_B.o:Filters/A_B.cpp
	@echo "Building Filters/A_B.o"
	@ ${CC} ${CFLAGS} -c ${INCLUDES} Filters/A_B.cpp -o Filters/A_B.o

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
	rm -f *.o *.d
	rm -f CmdTree/*.o CmdTree/*.d
	rm -f KeyProcessor/*.o KeyProcessor/*.d
	rm -f Filters/*.o Filters/*.d
	rm -f utinfra/*.o utinfra/*.d
	rm -f ${CLILIB}

-include $(OBJ:.o=.d)
