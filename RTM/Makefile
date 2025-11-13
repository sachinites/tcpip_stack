GCC=g++
TARGET=librtm.a

CFLAGS=-g -Wall -Wextra -fpermissive -I..
OBJS=rtm_driver.o \
		   rtm.o \
		   rtm_route.o \
		   rtm_nh.o \
		   rtm_show.o \
		   rtm_proto.o \
		   rtm_api.o \
		   rtm_priv_api.o \
		   rtm_resolution.o \
		   rtm_fib_interface.o \

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) rcs $(TARGET) $(OBJS)

%.o: %.cpp
	$(GCC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
