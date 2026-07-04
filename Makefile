CC=gcc
CFLAGS=-Wall -g

all:
	$(CC) $(CFLAGS) dbg.c -o mini-gdb
	$(CC) -g -no-pie target.c -o target

clean:
	rm -f mini-gdb target