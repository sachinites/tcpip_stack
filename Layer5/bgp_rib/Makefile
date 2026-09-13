GCC = g++
TARGET_LIB = libbgp_rib.a
TARGET_TEST = bgp_rib_test

CFLAGS ?= -g -Wall -Wextra -fpermissive -I../.. -I../../libs/c-hashtable $(SANITIZER_FLAGS) -MMD -MP

# Hashtable lives in libs/libstd.a for the main project. Standalone test
# links hashtable objects explicitly so it does not require libstd.
HASHTABLE_OBJS = \
	../../libs/c-hashtable/hashtable.o \
	../../libs/c-hashtable/hashtable_itr.o

OBJS = \
	bgp_rib_types.o \
	bgp_nlri_key.o \
	bgp_nlri_wire.o \
	bgp_rib.o \
	bgp_rib_vpnv4.o \
	bgp_rib_evpn.o

TEST_OBJS = bgp_rib_test.o

.PHONY: all test clean

all: $(TARGET_LIB)

test: $(TARGET_TEST)
	./$(TARGET_TEST)

$(TARGET_LIB): $(OBJS)
	ar rcs $(TARGET_LIB) $(OBJS)
	@echo "BGP RIB library $(TARGET_LIB) compiled successfully"

$(TARGET_TEST): $(TARGET_LIB) $(TEST_OBJS) $(HASHTABLE_OBJS)
	$(GCC) $(CFLAGS) $(SANITIZER_FLAGS) -o $(TARGET_TEST) \
		$(TEST_OBJS) $(HASHTABLE_OBJS) -L. -lbgp_rib

%.o: %.cpp
	$(GCC) $(CFLAGS) -c -o $@ $<

../../libs/c-hashtable/hashtable.o: ../../libs/c-hashtable/hashtable.c
	gcc $(CFLAGS) $(SANITIZER_FLAGS) -c ../../libs/c-hashtable/hashtable.c -o ../../libs/c-hashtable/hashtable.o

../../libs/c-hashtable/hashtable_itr.o: ../../libs/c-hashtable/hashtable_itr.c
	gcc $(CFLAGS) $(SANITIZER_FLAGS) -c ../../libs/c-hashtable/hashtable_itr.c -o ../../libs/c-hashtable/hashtable_itr.o

clean:
	rm -f $(OBJS) $(OBJS:.o=.d) $(TARGET_LIB) $(TARGET_TEST) bgp_rib_test.o bgp_rib_test.d

-include $(OBJS:.o=.d)
