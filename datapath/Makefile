CC=g++
#SANITIZER_FLAGS=-fsanitize=address,undefined

ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    DPDK_FLAGS += -mssse3
endif

ifeq ($(ARCH),aarch64)
    DPDK_FLAGS += -march=armv8-a+simd
endif

SANITIZER_FLAGS=
export CFLAGS=-g -Wcast-align -fpermissive ${DPDK_FLAGS} -Wall -Wextra -Wmissing-prototypes -Wold-style-definition -Wold-style-declaration -gdwarf-2 -g3 -Wignored-qualifiers -g ${SANITIZER_FLAGS}
AR=ar

TARGET=libdp.a

# Object files
OBJS=dp_init.o \
	 dp_cli.o \
	 dp_utils.o \
	 dp_uapi.o \
	 Interface/dp_intf_store.o \
	 Interface/dp_intf_recv_xmit.o \
	 Interface/dp_intf_log.o \
	 Vrfs/dp_vrf.o \
	 Layer2/arp/arp.o \
	 Layer2/switching/l2switch.o \
	 Layer2/switching/mac_table.o \
	 Layer2/vxlan/vlan_vni_ht.o \
	 Layer2/vxlan/vxlan_dp.o \
	 Layer2/l2fwd/ipv4-l2fwd.o \
	 FIB/fib_api.o \
	 FIB/fib.o \
	 FIB/fib_nh.o \
	 FIB/fib_route.o \
	 FIB/fib_show.o \
	 Layer3/layer3.o \
	 Layer3/ping.o \
	 Layer3/SRv6/srv6-end-behavior.o \
	 Layer3/SRv6/srv6-endpoint.o \
	 Layer3/Gre/gre-fwd.o \
	 Layer3/ipv4/ipv4-fwd.o \
	 Layer3/ipv6/ipv6-fwd.o \
	 Layer3/L3vpn/vpnv4.o \
	 dp-program/dp-prog-api.o \
	 dp-program/dp_msg_tr.o \

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

dp-program/%.o: dp-program/%.cpp
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

FIB/%.o: FIB/%.c FIB/%.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

Layer3/%.o: Layer3/%.cpp 
	$(CC) $(CFLAGS) -c -o $@ $<

Layer3/SRv6/%.o: Layer3/SRv6/%.cpp 
	$(CC) $(CFLAGS) -c -o $@ $<

Layer3/Gre/%.o: Layer3/Gre/%.cpp 
	$(CC) $(CFLAGS) -c -o $@ $<

Layer3/ipv4/%.o: Layer3/ipv4/%.cpp 
	$(CC) $(CFLAGS) -c -o $@ $<

Layer3/ipv6/%.o: Layer3/ipv6/%.cpp 
	$(CC) $(CFLAGS) -c -o $@ $<

Layer3/L3vpn/%.o: Layer3/L3vpn/%.cpp 
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
	rm -f FIB/*.o
	rm -f Layer3/*.o
	rm -f Layer3/SRv6/*.o
	rm -f Layer3/Gre/*.o
	rm -f Layer3/ipv4/*.o
	rm -f Layer3/ipv6/*.o
	rm -f Layer3/vpnv4/*.o
	rm -f dp-program/*.o

.PHONY: all clean
