CC=gcc
CFLAGS=-Wall -g

all:
	$(CC) $(CFLAGS) dbg.c -o mini-gdb
	$(CC) -g target.c -o target

clean:
	rm -f mini-gdb target