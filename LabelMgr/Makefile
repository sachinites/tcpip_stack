CC = g++

# libs/libstd.a is normally built (from the root Makefile) with whole-program
# ASAN/UBSAN instrumentation, so anything linking against it must be compiled
# and linked with the same sanitizer flags. Disable with: make SANITIZER_FLAGS=
SANITIZER_FLAGS ?= -fsanitize=address,undefined
export SANITIZER_FLAGS

export DPDK_CFLAGS := $(shell pkg-config --cflags libdpdk)

ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    DPDK_CFLAGS += -mssse3
endif

ifeq ($(ARCH),aarch64)
    DPDK_CFLAGS += -march=armv8-a+simd
endif

CFLAGS = -g -Wall -Wextra -fpermissive -Wcast-align -gdwarf-2 -g3 \
         -Wignored-qualifiers ${DPDK_CFLAGS} $(SANITIZER_FLAGS) -MMD -MP

LIB  = liblabelmgr.a
OBJS = label_mgr.o

.PHONY: all clean test

all: $(LIB)

$(LIB): $(OBJS)
	ar rcs $(LIB) $(OBJS)
	@echo "$(LIB) Build Finished"

label_mgr.o: label_mgr.cpp label_mgr.h
	$(CC) $(CFLAGS) -c -I . -I .. label_mgr.cpp -o label_mgr.o

# Standalone test/demo - not part of the main tcpstack.exe build.
# Usage: make test && ./label_mgr_test.exe
test: label_mgr_test.exe
	./label_mgr_test.exe

label_mgr_test.exe: label_mgr_test.o $(LIB) ../libs/libstd.a
	$(CC) $(CFLAGS) label_mgr_test.o $(LIB) -L../libs -lstd -o label_mgr_test.exe

label_mgr_test.o: label_mgr_test.cpp label_mgr.h
	$(CC) $(CFLAGS) -c -I . label_mgr_test.cpp -o label_mgr_test.o

../libs/libstd.a:
	(cd ../libs; make)

clean:
	rm -f *.o *.d *.a *.exe

-include $(OBJS:.o=.d)
