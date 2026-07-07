#include "cmd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* bison/flex interface (generated with %define api.prefix {cmdyy}) */
int cmdyyparse(void);
void cmdyyrestart(FILE *input_file);
typedef struct yy_buffer_state *YY_BUFFER_STATE;
YY_BUFFER_STATE cmdyy_scan_string(const char *yy_str);
void cmdyy_delete_buffer(YY_BUFFER_STATE b);

/* defined in cmd_parser.y */
extern cmd_t cmd_parsed_result;
extern char cmd_parse_error[256];

static void cmd_reset_result(void)
{
    cmd_free(&cmd_parsed_result);
    memset(&cmd_parsed_result, 0, sizeof(cmd_parsed_result));
    cmd_parse_error[0] = '\0';
}

static void trim_arg_inplace(char *s)
{
    char *p;
    size_t len;

    if (!s)
        return;

    p = s;
    while (*p == ' ' || *p == '\t')
        p++;

    if (p != s)
        memmove(s, p, strlen(p) + 1);

    len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t'))
        s[--len] = '\0';
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

    memset(out, 0, sizeof(*out));

    if (errbuf && errbufsz)
        errbuf[0] = '\0';

    const char *p = line ? line : "";
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '\0' || *p == '\n' || *p == '\r') {
        out->kind = CMD_INVALID;
        out->arg = NULL;
        return 0;
    }

    cmd_reset_result();

    YY_BUFFER_STATE buf = cmdyy_scan_string(line ? line : "");

    int rc = cmdyyparse();

    cmdyy_delete_buffer(buf);

    if (rc != 0) {
        if (errbuf && errbufsz) {
            snprintf(errbuf, errbufsz, "%s",
                     cmd_parse_error[0] ? cmd_parse_error : "parse error");
        }
        return -1;
    }

    *out = cmd_parsed_result;
    if (out->arg)
        trim_arg_inplace(out->arg);
    memset(&cmd_parsed_result, 0, sizeof(cmd_parsed_result));

    if (errbuf && errbufsz)
        errbuf[0] = '\0';

    return 0;
}

