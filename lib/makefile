CC=gcc
CFLAGS=-I/usr/include -g -Wall -fPIC
LDFLAGS=-shared -lldap -llber -lkrb5

SRCS=dacledit.c
OBJS=$(SRCS:.c=.o)
TARGET=libdacledit.so

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(OBJS) $(TARGET)