CC=g++
CFLAGS=-g -Wall -Wextra -fpermissive -I..
AR=ar

TARGET=libdp.a

# Object files
OBJS=dp_init.o \
	 dp_cli.o \
	 Interface/dp_intf_store.o \
	 Interface/dp_intf_update.o \
	 Vrfs/dp_vrf.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) rcs $(TARGET) $(OBJS)

# Pattern rule for compiling .cpp files in current directory
%.o: %.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

# Pattern rule for compiling .cpp files in Interface subdirectory
Interface/%.o: Interface/%.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

# Pattern rule for compiling .cpp files in Vrfs subdirectory
Vrfs/%.o: Vrfs/%.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
	rm -f *.o
	rm -f Interface/*.o
	rm -f Vrfs/*.o

.PHONY: all clean
