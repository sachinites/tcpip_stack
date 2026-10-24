#!/bin/bash
# Builds the lock-less Event Dispatcher and its demo/test program.
# Needs DPDK installed and visible to pkg-config (pkg-config --modversion libdpdk).
# Only librte_ring and librte_eal are linked; rte_eal_init() is NOT required.
set -e
cd "$(dirname "$0")"

DPDK_CFLAGS=$(pkg-config --cflags libdpdk)
DPDK_LIBS="-L$(pkg-config --variable=libdir libdpdk) -lrte_ring -lrte_eal -lrte_log"

g++ -g -O2 -Wall -Wextra -std=c++17 $DPDK_CFLAGS $EXTRA_CFLAGS -c LockLessEvDis.cpp -o LockLessEvDis.o
g++ -g -O2 -Wall -Wextra -std=c++17 $DPDK_CFLAGS $EXTRA_CFLAGS -c LockLessEvDis_test.cpp -o LockLessEvDis_test.o
g++ -g -O2 -Wall -Wextra -std=c++17 $DPDK_CFLAGS $EXTRA_CFLAGS -c LockLessEvDis_usage.cpp -o LockLessEvDis_usage.o
g++ -g LockLessEvDis.o LockLessEvDis_test.o -o ll_ev_dis_test.exe $DPDK_LIBS -lpthread
g++ -g LockLessEvDis.o LockLessEvDis_usage.o -o ll_ev_dis_usage.exe $DPDK_LIBS -lpthread

echo "Built ll_ev_dis_test.exe ll_ev_dis_usage.exe"
