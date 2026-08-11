GCC=g++
TARGET=librtm.a

export DPDK_CFLAGS := $(shell pkg-config --cflags libdpdk)

ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    DPDK_CFLAGS += -mssse3
endif

ifeq ($(ARCH),aarch64)
    DPDK_CFLAGS += -march=armv8-a+simd
endif

export CFLAGS=-g -Wall -Wextra -fpermissive -I.. ${DPDK_CFLAGS} ${SANITIZER_FLAGS} -MMD -MP

OBJS=rtm.o \
     rtm_route.o \
	 rtm_nh.o \
	 rtm_show.o \
	 rtm_priv_api.o \
	 rtm_proto.o \
	 rtm_resolution.o \
	 rtm_fib_interface.o \
	 rtm_nb_integ.o \
	 rtm_presentation.o \
	 rtm_gc.o \
	 rtm_fib_common.o \
	 rtm_dist_mgr.o \
	 rtm_dist_cli.o \
	 rtm_ext_calls.o \

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) rcs $(TARGET) $(OBJS)

%.o: %.cpp
	$(GCC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(OBJS:.o=.d) $(TARGET)

-include $(OBJS:.o=.d)

.PHONY: all clean
