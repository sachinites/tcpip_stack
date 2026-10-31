GCC = g++
TARGET_LIB = libbgp_rib.a
TARGET_TEST = bgp_rib_test

# Match top-level Makefile so standalone test links against libstd object files.
SANITIZER_FLAGS ?= -fsanitize=address,undefined
export SANITIZER_FLAGS

CFLAGS ?= -g -Wall -Wextra -fpermissive -I../.. -I../../libs/c-hashtable $(SANITIZER_FLAGS) -MMD -MP

# Hashtable lives in libs/libstd.a for the main project. Standalone test
# links hashtable objects explicitly so it does not require libstd.
HASHTABLE_OBJS = \
	../../libs/c-hashtable/hashtable.o \
	../../libs/c-hashtable/hashtable_itr.o

LIBTREE_OBJ = ../../libs/Tree/avl.o

CMN_OBJS = \
	../../libs/BitOp/bitmap.o \
	../../libs/common/mpls_lstack.o \
	../../libs/common/ipv6_utils.o \
	../../libs/common/cmn_prefix.o

OBJS = \
	bgp_rib_types.o \
	bgp_nlri_key.o \
	bgp_nlri_wire.o \
	bgp_rib.o \
	bgp_rib_ipv4.o \
	bgp_rib_vpnv4.o \
	bgp_rib_evpn.o

TEST_OBJS = bgp_rib_test.o

.DEFAULT_GOAL := all

.PHONY: all test clean cmn_deps

all: $(TARGET_LIB)

test: cmn_deps $(TARGET_TEST)
	./$(TARGET_TEST)

cmn_deps:
	$(MAKE) -C ../../libs Tree/avl.o BitOp/bitmap.o common/mpls_lstack.o common/ipv6_utils.o common/cmn_prefix.o

$(TARGET_LIB): $(OBJS)
	ar rcs $(TARGET_LIB) $(OBJS)
	@echo "BGP RIB library $(TARGET_LIB) compiled successfully"

$(TARGET_TEST): $(TARGET_LIB) $(TEST_OBJS) $(HASHTABLE_OBJS) $(LIBTREE_OBJ) $(CMN_OBJS)
	$(GCC) $(CFLAGS) -o $(TARGET_TEST) \
		$(TEST_OBJS) $(HASHTABLE_OBJS) $(LIBTREE_OBJ) $(CMN_OBJS) -L. -lbgp_rib -lm

../../libs/Tree/avl.o: ../../libs/Tree/avl.c
	gcc $(CFLAGS) -I../../libs/Tree -c ../../libs/Tree/avl.c -o ../../libs/Tree/avl.o

%.o: %.cpp
	$(GCC) $(CFLAGS) -c -o $@ $<

../../libs/c-hashtable/hashtable.o: ../../libs/c-hashtable/hashtable.c
	gcc $(CFLAGS) -c ../../libs/c-hashtable/hashtable.c -o ../../libs/c-hashtable/hashtable.o

../../libs/c-hashtable/hashtable_itr.o: ../../libs/c-hashtable/hashtable_itr.c
	gcc $(CFLAGS) -c ../../libs/c-hashtable/hashtable_itr.c -o ../../libs/c-hashtable/hashtable_itr.o

clean:
	rm -f $(OBJS) $(OBJS:.o=.d) $(TARGET_LIB) $(TARGET_TEST) bgp_rib_test.o bgp_rib_test.d

-include $(OBJS:.o=.d)
