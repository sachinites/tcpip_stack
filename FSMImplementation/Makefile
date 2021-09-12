CC=gcc
CFLAGS= -g
FSMLIB=libfsm.a
TARGET:${FSMLIB}
${FSMLIB}:fsm.o std_fsm.o
	@echo "Building "${FSMLIB}
	ar rs ${FSMLIB} fsm.o std_fsm.o
fsm.o:fsm.c
	@echo "Building fsm.o"
	${CC} ${CFLAGS} -c fsm.c -o fsm.o
std_fsm.o:std_fsm.c
	@echo "Building std_fsm.o"
	${CC} ${CFLAGS} -c std_fsm.c -o std_fsm.o
clean:
	@echo "Cleaning built objects"
	rm -f *.o
	rm -f *exe	
	rm -f *.a
