CC=g++
CFLAGS=-g -Wall -Wextra -fpermissive -I..
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

