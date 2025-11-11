CC=g++
CFLAGS=-g -Wall -Wextra -fpermissive -I..
AR=ar

TARGET=libfib.a

OBJS=fib.o \
	 fib_api.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) rcs $(TARGET) $(OBJS)

fib.o: fib.cpp fib.h fib_api.h fib_common.h fib_enums.h fib_route.h fib_nh.h fib_error.h
	$(CC) $(CFLAGS) -c fib.cpp -o fib.o

fib_api.o: fib_api.cpp fib_api.h fib.h fib_common.h fib_enums.h fib_route.h fib_nh.h
	$(CC) $(CFLAGS) -c fib_api.cpp -o fib_api.o

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean

