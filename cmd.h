#ifndef CMD_H
#define CMD_H

#include <stddef.h>

typedef enum {
    CMD_INVALID = 0,
    CMD_RUN,
    CMD_C,
    CMD_S,
    CMD_SI,
    CMD_N,
    CMD_UP,
    CMD_KILL,
    CMD_REGS,
    CMD_SYMS,
    CMD_TB,
    CMD_LIST,
    CMD_DIS,
    CMD_BREAK,
    CMD_DEL,
    CMD_SHOW,
    CMD_DBG,
    CMD_LINES,
    CMD_X,
    CMD_PRINT,
    CMD_SET,
    CMD_HELP,
    CMD_QUIT,
} cmd_kind_t;

typedef struct {
    cmd_kind_t kind;
    char *arg; /* optional, heap-allocated */
} cmd_t;

/* Parses one input line into a command.
 * Returns 0 on success (including CMD_INVALID when empty/whitespace),
 * non-zero on parse error. */
int cmd_parse_line(const char *line, cmd_t *out,
                   char *errbuf, size_t errbufsz);

void cmd_free(cmd_t *cmd);

#endif

