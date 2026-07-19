#include "cmd.h"

#include <stdlib.h>
#include <string.h>

static const char *skip_ws(const char *p)
{
    while (p && (*p == ' ' || *p == '\t'))
        p++;
    return p;
}

static char *dup_str(const char *s)
{
    if (!s)
        return NULL;
    size_t n = strlen(s);
    char *r = (char *)malloc(n + 1);
    if (!r)
        return NULL;
    memcpy(r, s, n + 1);
    return r;
}

static int is_word_char(char c)
{
    return (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           c == '_' || c == '-' || c == '.';
}

static char *dup_first_word(const char *p, const char **rest_out)
{
    p = skip_ws(p);
    if (!p || !*p)
        return NULL;

    const char *start = p;
    while (*p && is_word_char(*p))
        p++;

    if (p == start)
        return NULL;

    size_t n = (size_t)(p - start);
    char *w = (char *)malloc(n + 1);
    if (!w)
        return NULL;
    memcpy(w, start, n);
    w[n] = '\0';

    if (rest_out)
        *rest_out = p;
    return w;
}

void cmd_free(cmd_t *cmd)
{
    if (!cmd)
        return;
    free(cmd->arg);
    cmd->arg = NULL;
    cmd->kind = CMD_INVALID;
}

int cmd_parse_line(const char *line, cmd_t *out,
                   char *errbuf, size_t errbufsz)
{
    if (!out)
        return -1;

    cmd_free(out);

    if (errbuf && errbufsz)
        errbuf[0] = '\0';

    const char *p = line ? line : "";
    p = skip_ws(p);

    if (*p == '\0' || *p == '\n' || *p == '\r') {
        out->kind = CMD_INVALID;
        out->arg = NULL;
        return 0;
    }

    const char *rest = NULL;
    char *cmd = dup_first_word(p, &rest);
    if (!cmd) {
        if (errbuf && errbufsz)
            strncpy(errbuf, "parse error", errbufsz - 1), errbuf[errbufsz - 1] = '\0';
        return -1;
    }

    rest = rest ? rest : "";
    rest = skip_ws(rest);

    /* strip trailing newline(s) for arg */
    char tmp[512];
    strncpy(tmp, rest, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    size_t len = strlen(tmp);
    while (len > 0 && (tmp[len - 1] == '\n' || tmp[len - 1] == '\r'))
        tmp[--len] = '\0';

    if (!strcmp(cmd, "run")) {
        /* run takes one word as program path (same as old behavior) */
        const char *after = NULL;
        char *prog = dup_first_word(rest, &after);
        out->kind = CMD_RUN;
        out->arg = prog ? prog : dup_str("");
    } else if (!strcmp(cmd, "c")) {
        out->kind = CMD_C;
    } else if (!strcmp(cmd, "s")) {
        out->kind = CMD_S;
    } else if (!strcmp(cmd, "si")) {
        out->kind = CMD_SI;
    } else if (!strcmp(cmd, "n")) {
        out->kind = CMD_N;
    } else if (!strcmp(cmd, "up")) {
        out->kind = CMD_UP;
    } else if (!strcmp(cmd, "kill")) {
        out->kind = CMD_KILL;
    } else if (!strcmp(cmd, "watch")) {
        out->kind = CMD_WATCH;
        out->arg = dup_str(tmp);
    } else if (!strcmp(cmd, "threads")) {
        out->kind = CMD_THREADS;
    } else if (!strcmp(cmd, "thread")) {
        out->kind = CMD_THREAD;
        out->arg = dup_str(tmp);
    } else if (!strcmp(cmd, "regs")) {
        out->kind = CMD_REGS;
    } else if (!strcmp(cmd, "syms")) {
        out->kind = CMD_SYMS;
    } else if (!strcmp(cmd, "tb")) {
        out->kind = CMD_TB;
    } else if (!strcmp(cmd, "l") || !strcmp(cmd, "list")) {
        out->kind = CMD_LIST;
        out->arg = dup_str(tmp);
    } else if (!strcmp(cmd, "dis")) {
        out->kind = CMD_DIS;
        out->arg = dup_str(tmp);
    } else if (!strcmp(cmd, "b") || !strcmp(cmd, "break")) {
        out->kind = CMD_BREAK;
        out->arg = dup_str(tmp);
    } else if (!strcmp(cmd, "del") || !strcmp(cmd, "delete")) {
        out->kind = CMD_DEL;
        out->arg = dup_str(tmp);
    } else if (!strcmp(cmd, "show")) {
        out->kind = CMD_SHOW;
        out->arg = dup_str(tmp);
    } else if (!strcmp(cmd, "dbg")) {
        out->kind = CMD_DBG;
        out->arg = dup_str(tmp);
    } else if (!strcmp(cmd, "lines")) {
        out->kind = CMD_LINES;
        out->arg = dup_str(tmp);
    } else if (!strcmp(cmd, "x")) {
        out->kind = CMD_X;
        out->arg = dup_str(tmp);
    } else if (!strcmp(cmd, "p") || !strcmp(cmd, "print")) {
        out->kind = CMD_PRINT;
        out->arg = dup_str(tmp);
    } else if (!strcmp(cmd, "set")) {
        out->kind = CMD_SET;
        out->arg = dup_str(tmp);
    } else if (!strcmp(cmd, "help")) {
        out->kind = CMD_HELP;
    } else if (!strcmp(cmd, "q")) {
        out->kind = CMD_QUIT;
    } else {
        if (errbuf && errbufsz) {
            strncpy(errbuf, "unknown command", errbufsz - 1);
            errbuf[errbufsz - 1] = '\0';
        }
        free(cmd);
        return -1;
    }

    free(cmd);
    if ((out->kind == CMD_LIST || out->kind == CMD_DIS || out->kind == CMD_BREAK ||
         out->kind == CMD_SHOW || out->kind == CMD_DBG || out->kind == CMD_LINES ||
         out->kind == CMD_X || out->kind == CMD_PRINT || out->kind == CMD_SET) &&
        !out->arg) {
        /* OOM */
        if (errbuf && errbufsz) {
            strncpy(errbuf, "out of memory", errbufsz - 1);
            errbuf[errbufsz - 1] = '\0';
        }
        cmd_free(out);
        return -1;
    }

    return 0;
}

