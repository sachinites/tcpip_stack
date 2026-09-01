CXX := g++
AR := ar

CXXFLAGS := -std=c++17 -Wall -Wextra -O2
CPPFLAGS := -I./generated $(shell pkg-config --cflags grpc++ protobuf)

BUILD_DIR := build
GENERATED_SRCS := $(wildcard generated/api/*.pb.cc)
GENERATED_OBJS := $(patsubst generated/api/%.cc,$(BUILD_DIR)/%.o,$(GENERATED_SRCS))
WRAPPER_OBJ := $(BUILD_DIR)/gobgp_grpc.o

LIBRARY := libgrpc_wrapper.a
TEST := test.exe

GRPC_STATIC_LIBS := $(shell pkg-config --libs --static grpc++ protobuf)

.PHONY: all clean test

all: $(LIBRARY)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(WRAPPER_OBJ): gobgp_grpc.cpp gobgp_grpc.h | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: generated/api/%.cc | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@

$(LIBRARY): $(WRAPPER_OBJ) $(GENERATED_OBJS)
	$(AR) rcs $@ $^

$(TEST): test.cpp $(LIBRARY)
	$(CXX) $(CXXFLAGS) -I. $(CPPFLAGS) \
	    test.cpp \
	    -L. \
	    -Wl,--start-group \
	    -lgrpc_wrapper \
	    $(GRPC_STATIC_LIBS) \
	    -Wl,--end-group \
	    -ldl \
	    -pthread \
	    -o $@

test: $(TEST)
	./$(TEST)

clean:
	rm -rf $(BUILD_DIR) $(LIBRARY) $(TEST)