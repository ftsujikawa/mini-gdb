CC=gcc
CFLAGS=-Wall -g

SRCS=dbg_globals.c util.c memory.c dwarf.c expr.c sym.c exec.c ui.c
OBJS=$(SRCS:.c=.o)

all: tdb target

tdb: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o tdb

target: target.c
	$(CC) -g target.c -o target

clean:
	rm -f tdb target $(OBJS)
