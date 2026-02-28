CC=g++
CFLAGS=-g -Wall -Wextra -fpermissive -I..
AR=ar

TARGET=libdp.a

# Object files
OBJS=dp_init.o \
	 dp_cli.o \
	 dp_utils.o \
	 Interface/dp_intf_store.o \
	 Interface/dp_intf_update.o \
	 Interface/dp_intf_xmit.o \
	 Interface/dp_intf_log.o \
	 Vrfs/dp_vrf.o \
	 Layer2/arp/arp.o \
	 Layer2/switching/l2switch.o \
	 Layer2/switching/mac_table.o \
	 Layer2/vxlan/vlan_vni_ht.o \
	 Layer2/vxlan/vxlan_dp.o \
	 Layer2/l2fwd/ipv4-l2fwd.o \


all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) rcs $(TARGET) $(OBJS)

# Pattern rule for compiling .cpp files in current directory
%.o: %.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Pattern rule for compiling .cpp files in Interface subdirectory
Interface/%.o: Interface/%.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

# Pattern rule for compiling .cpp files in Vrfs subdirectory
Vrfs/%.o: Vrfs/%.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

Layer2/arp/%.o: Layer2/arp/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

Layer2/switching/%.o: Layer2/switching/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

Layer2/vxlan/%.o: Layer2/vxlan/%.c Layer2/vxlan/%.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

Layer2/l2fwd/%.o: Layer2/l2fwd/%.c Layer2/l2fwd/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
	rm -f *.o
	rm -f Interface/*.o
	rm -f Vrfs/*.o
	rm -f Layer2/arp/*.o
	rm -f Layer2/switching/*.o
	rm -f Layer2/vxlan/*.o
	rm -f Layer2/l2fwd/*.o

.PHONY: all clean
