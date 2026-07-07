%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmd.h"

cmd_t cmd_parsed_result = {0};
char cmd_parse_error[256] = {0};

static void set_cmd(cmd_kind_t kind, char *arg)
{
    cmd_parsed_result.kind = kind;
    cmd_parsed_result.arg = arg;
}

int cmdyylex(void);
void cmdyyerror(const char *s);
%}

%define api.prefix {cmdyy}

%union {
    char *str;
}

%token T_EOL
%token <str> T_WORD
%token <str> T_REST

%token T_RUN T_C T_S T_SI T_N T_UP T_REGS T_SYMS T_TB
%token T_L T_LIST T_DIS T_B T_BREAK T_SHOW T_DBG T_LINES T_X
%token T_P T_PRINT T_SET
%token T_HELP T_Q

%%

input
    : line
    ;

opt_eol
    : /* empty */
    | T_EOL
    ;

line
    : T_EOL
        { set_cmd(CMD_INVALID, NULL); }
    | T_RUN T_WORD T_EOL
        { set_cmd(CMD_RUN, $2); }
    | T_C T_EOL
        { set_cmd(CMD_C, NULL); }
    | T_S T_EOL
        { set_cmd(CMD_S, NULL); }
    | T_SI T_EOL
        { set_cmd(CMD_SI, NULL); }
    | T_N T_EOL
        { set_cmd(CMD_N, NULL); }
    | T_UP T_EOL
        { set_cmd(CMD_UP, NULL); }
    | T_REGS T_EOL
        { set_cmd(CMD_REGS, NULL); }
    | T_SYMS T_EOL
        { set_cmd(CMD_SYMS, NULL); }
    | T_TB T_EOL
        { set_cmd(CMD_TB, NULL); }
    | T_HELP T_EOL
        { set_cmd(CMD_HELP, NULL); }
    | T_Q T_EOL
        { set_cmd(CMD_QUIT, NULL); }

    | T_L T_REST opt_eol
        { set_cmd(CMD_LIST, $2); }
    | T_LIST T_REST opt_eol
        { set_cmd(CMD_LIST, $2); }

    | T_DIS T_REST opt_eol
        { set_cmd(CMD_DIS, $2); }

    | T_B T_REST opt_eol
        { set_cmd(CMD_BREAK, $2); }
    | T_BREAK T_REST opt_eol
        { set_cmd(CMD_BREAK, $2); }

    | T_SHOW T_REST opt_eol
        { set_cmd(CMD_SHOW, $2); }

    | T_DBG T_REST opt_eol
        { set_cmd(CMD_DBG, $2); }

    | T_LINES T_REST opt_eol
        { set_cmd(CMD_LINES, $2); }

    | T_X T_REST opt_eol
        { set_cmd(CMD_X, $2); }

    | T_P T_REST opt_eol
        { set_cmd(CMD_PRINT, $2); }
    | T_PRINT T_REST opt_eol
        { set_cmd(CMD_PRINT, $2); }

    | T_SET T_REST opt_eol
        { set_cmd(CMD_SET, $2); }

    | T_WORD T_EOL
        {
            free($1);
            snprintf(cmd_parse_error, sizeof(cmd_parse_error),
                     "unknown command");
            YYABORT;
        }
    ;

%%

void cmdyyerror(const char *s)
{
    if (!cmd_parse_error[0]) {
        snprintf(cmd_parse_error, sizeof(cmd_parse_error), "%s", s);
    }
}
