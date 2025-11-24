GCC=g++
TARGET=librtm.a

CFLAGS=-g -Wall -Wextra -fpermissive -I..
OBJS= rtm.o \
       		rtm_route.o \
		   rtm_nh.o \
		   rtm_show.o \
		   rtm_priv_api.o \
		   rtm_proto.o \
		   rtm_resolution.o \
		   rtm_fib_interface.o \
		   rtm_common.o \
		   rtm_nb_integ.o \
		   rtm_presentation.o \

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) rcs $(TARGET) $(OBJS)

%.o: %.cpp
	$(GCC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
