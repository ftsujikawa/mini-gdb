CC=gcc
CFLAGS=-Wall -g

SRCS=dbg_globals.c util.c memory.c dwarf.c expr.c sym.c exec.c ui.c
OBJS=$(SRCS:.c=.o)

all: mini-gdb target

mini-gdb: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o mini-gdb

target: target.c
	$(CC) -g target.c -o target

clean:
	rm -f mini-gdb target $(OBJS)
