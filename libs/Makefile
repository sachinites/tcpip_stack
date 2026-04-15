CC     = g++
#SANITIZER_FLAGS = -fsanitize=address,undefined
SANITIZER_FLAGS =

#https://stackoverflow.com/questions/69212557/dpdk-compilation-error-while-freeing-mbuf
DPDK_FLAGS=-mssse3

CFLAGS = -g -Wcast-align -fpermissive ${DPDK_FLAGS} -Wall -Wextra -Wmissing-prototypes \
         -Wold-style-definition -Wold-style-declaration -gdwarf-2 -g3 \
         -Wignored-qualifiers $(SANITIZER_FLAGS)

TARGET = libstd.a

# Install external dependent libs:  sudo apt-get install libpq-dev

OBJS = std_lib_init.o 						  \
	   BitOp/bitmap.o                     \
       c-hashtable/hashtable.o            \
       c-hashtable/hashtable_itr.o        \
       EventDispatcher/event_dispatcher.o \
       gluethread/glthread.o              \
       libtimer/WheelTimer.o             \
       libtimer/timerlib.o               \
       LinuxMemoryManager/mm.o           \
       mtrie/mtrie.o                     \
       notifc/notif.o                    \
       pkt-block/pkt_block.o             \
       prefix-list/prefixlst.o           \
       stack/stack.o                     \
       Tracer/tracer.o                   \
       Tree/avl.o                        \
	   common/ipv6_utils.o               \
	   common/cmn_prefix.o

$(TARGET): $(OBJS)
	ar rcs $(TARGET) $(OBJS)
	@echo "$(TARGET) Build Finished"

std_lib_init.o:  std_lib_init.c 
	$(CC) $(CFLAGS) -c std_lib_init.c -o std_lib_init.o

# BitOp
BitOp/bitmap.o: BitOp/bitmap.c
	$(CC) $(CFLAGS) -c BitOp/bitmap.c -o BitOp/bitmap.o

# c-hashtable
c-hashtable/hashtable.o: c-hashtable/hashtable.c
	$(CC) $(CFLAGS) -c c-hashtable/hashtable.c -o c-hashtable/hashtable.o

c-hashtable/hashtable_itr.o: c-hashtable/hashtable_itr.c
	$(CC) $(CFLAGS) -c c-hashtable/hashtable_itr.c -o c-hashtable/hashtable_itr.o

# EventDispatcher
EventDispatcher/event_dispatcher.o: EventDispatcher/event_dispatcher.c
	$(CC) $(CFLAGS) -c -I EventDispatcher -I gluethread \
		EventDispatcher/event_dispatcher.c -o EventDispatcher/event_dispatcher.o

# gluethread
gluethread/glthread.o: gluethread/glthread.c
	$(CC) $(CFLAGS) -c -I gluethread gluethread/glthread.c -o gluethread/glthread.o

# libtimer
libtimer/WheelTimer.o: libtimer/WheelTimer.c
	$(CC) $(CFLAGS) -c -I gluethread -I libtimer libtimer/WheelTimer.c -o libtimer/WheelTimer.o

libtimer/timerlib.o: libtimer/timerlib.c
	$(CC) $(CFLAGS) -c -I gluethread -I libtimer libtimer/timerlib.c -o libtimer/timerlib.o

# LinuxMemoryManager
LinuxMemoryManager/mm.o: LinuxMemoryManager/mm.c
	$(CC) $(CFLAGS) -c -I LinuxMemoryManager LinuxMemoryManager/mm.c -o LinuxMemoryManager/mm.o

# mtrie
mtrie/mtrie.o: mtrie/mtrie.c
	$(CC) $(CFLAGS) -c -I mtrie mtrie/mtrie.c -o mtrie/mtrie.o

# notifc
notifc/notif.o: notifc/notif.c
	$(CC) $(CFLAGS) -c -I notifc -I . notifc/notif.c -o notifc/notif.o

# pkt-block
pkt-block/pkt_block.o: pkt-block/pkt_block.c
	$(CC) $(CFLAGS) -c -I . -I pkt-block pkt-block/pkt_block.c -o pkt-block/pkt_block.o

# prefix-list
prefix-list/prefixlst.o:prefix-list/prefixlst.c
	$(CC) $(CFLAGS) -c -I . prefix-list/prefixlst.c -o prefix-list/prefixlst.o

# stack
stack/stack.o:stack/stack.c
	$(CC) $(CFLAGS) -c stack/stack.c -o stack/stack.o

# Tracer
Tracer/tracer.o: Tracer/tracer.cpp
	$(CC) $(CFLAGS) -c -I Tracer Tracer/tracer.cpp -o Tracer/tracer.o

# Tree
Tree/avl.o:Tree/avl.c
	$(CC) $(CFLAGS) -c -I Tree Tree/avl.c -o Tree/avl.o

common/ipv6_utils.o:common/ipv6_utils.cpp
	$(CC) $(CFLAGS) -c -I common common/ipv6_utils.cpp -o common/ipv6_utils.o

common/cmn_prefix.o:common/cmn_prefix.cpp
	$(CC) $(CFLAGS) -c -I common common/cmn_prefix.cpp -o common/cmn_prefix.o

clean:
	rm -f $(TARGET)
	rm -f BitOp/*.o
	rm -f c-hashtable/*.o
	rm -f EventDispatcher/*.o
	rm -f gluethread/*.o
	rm -f libtimer/*.o
	rm -f LinuxMemoryManager/*.o
	rm -f mtrie/*.o
	rm -f notifc/*.o
	rm -f packet-tracer/*.o
	rm -f pkt-block/*.o
	rm -f prefix-list/*.o
	rm -f stack/*.o
	rm -f Tracer/*.o
	rm -f Tree/*.o
	rm -f common/*.o
	rm -f *.o

all:
	make
