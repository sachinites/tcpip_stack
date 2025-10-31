GCC=g++
TARGET=rtm.exe

OBJS=rtm_driver.o rtm_api.o rtm_global.o rtm_show.o


all: $(TARGET)

$(TARGET): $(OBJS)
	$(GCC) -o $(TARGET) $(OBJS) ../Tree/avl.o

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
