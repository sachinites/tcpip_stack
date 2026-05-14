CC=g++

export DPDK_CFLAGS := $(shell pkg-config --cflags libdpdk)

ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    DPDK_CFLAGS += -mssse3
endif

ifeq ($(ARCH),aarch64)
    DPDK_CFLAGS += -march=armv8-a+simd
endif

CFLAGS=-g -Wall -Wextra -fpermissive -I.. ${DPDK_CFLAGS}
AR=ar

TARGET=libfib.a

OBJS=fib.o \
	 fib_api.o \
	 fib_route.o \
	 fib_nh.o \
	 fib_show.o \

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) rcs $(TARGET) $(OBJS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean

