GCC=g++
TARGET=rtm.exe

CFLAGS=-g
OBJS=rtm_driver.o rtm.o rtm_route.o rtm_nh.o rtm_show.o rtm_proto.o rtm_api.o rtm_priv_api.o


all: $(TARGET)

$(TARGET): $(OBJS)
	$(GCC) $(CFLAGS) -o $(TARGET) $(OBJS) ../Tree/avl.o ../gluethread/glthread.o

%.o: %.cpp
	$(GCC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
