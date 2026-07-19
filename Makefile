CC=gcc
CFLAGS=-Wall -g

CORE_SRCS=dbg_globals.c util.c memory.c dwarf.c expr.c sym.c exec.c ui.c heap.c

HAVE_BISON:=$(shell command -v bison 2>/dev/null)
HAVE_FLEX:=$(shell command -v flex 2>/dev/null)

ifeq ($(strip $(HAVE_BISON)$(HAVE_FLEX)),)
  SRCS=$(CORE_SRCS) cmd.c
else
  SRCS=$(CORE_SRCS) cmd_bison.c cmd_parser.c cmd_lexer.c \
	expr_ast.c expr_parse.c expr_eval_ast.c expr_parser.c expr_lexer.c
  CFLAGS+=-DHAVE_EXPR_BISON
endif

OBJS=$(SRCS:.c=.o)

all: tdb target leak_target thread_target

tdb: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o tdb

target: target.c
	$(CC) -g target.c -o target

leak_target: leak_target.c
	$(CC) -g leak_target.c -o leak_target

thread_target: thread_target.c
	$(CC) -g -pthread thread_target.c -o thread_target

clean:
	rm -f tdb target leak_target thread_target *.o \
		cmd_parser.c cmd_parser.h cmd_lexer.c \
		expr_parser.c expr_parser.h expr_lexer.c

cmd_parser.c cmd_parser.h: cmd_parser.y
	bison -d -o cmd_parser.c cmd_parser.y

cmd_lexer.c: cmd_lexer.l cmd_parser.h
	flex -o cmd_lexer.c cmd_lexer.l

expr_parser.c expr_parser.h: expr_parser.y
	bison -d -o expr_parser.c expr_parser.y

expr_lexer.c: expr_lexer.l expr_parser.h
	flex -o expr_lexer.c expr_lexer.l
