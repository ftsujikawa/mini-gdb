%option noyywrap nounput noinput
%option prefix="cmdyy"

%x ARG

%{
#include <stdlib.h>
#include <string.h>

#include "cmd.h"
#include "cmd_parser.h"

static char *dup_yytext(void)
{
    size_t n = (size_t)yyleng;
    char *s = (char *)malloc(n + 1);
    if (!s)
        return NULL;
    memcpy(s, yytext, n);
    s[n] = '\0';
    return s;
}
%}

WS      [ \t]+
EOL     (\r?\n)

%%

{WS}                    ;

<INITIAL>{
"run"                   return T_RUN;
"c"                     return T_C;
"si"                    return T_SI;
"s"                     return T_S;
"n"                     return T_N;
"up"                    return T_UP;
"regs"                  return T_REGS;
"syms"                  return T_SYMS;
"tb"                    return T_TB;
"list"                  { BEGIN(ARG); return T_LIST; }
"l"                     { BEGIN(ARG); return T_L; }
"dis"                   { BEGIN(ARG); return T_DIS; }
"break"                 { BEGIN(ARG); return T_BREAK; }
"b"                     { BEGIN(ARG); return T_B; }
"delete"                { BEGIN(ARG); return T_DELETE; }
"del"                   { BEGIN(ARG); return T_DEL; }
"show"                  { BEGIN(ARG); return T_SHOW; }
"dbg"                   { BEGIN(ARG); return T_DBG; }
"lines"                 { BEGIN(ARG); return T_LINES; }
"x"                     { BEGIN(ARG); return T_X; }
"print"                 { BEGIN(ARG); return T_PRINT; }
"p"                     { BEGIN(ARG); return T_P; }
"set"                   { BEGIN(ARG); return T_SET; }
"help"                  return T_HELP;
"q"                     return T_Q;
[^ \t\r\n]+             { cmdyylval.str = dup_yytext(); return T_WORD; }
}

<ARG>{
{WS}+                   ;
[^\r\n]+                {
                            cmdyylval.str = dup_yytext();
                            BEGIN(INITIAL);
                            return T_REST;
                        }
{EOL}                   {
                            cmdyylval.str = strdup("");
                            BEGIN(INITIAL);
                            return T_REST;
                        }
}

{EOL}                   { BEGIN(INITIAL); return T_EOL; }
<<EOF>>                 { BEGIN(INITIAL); return 0; }

%%
