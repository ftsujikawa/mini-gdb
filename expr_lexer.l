%option noyywrap nounput noinput
%option prefix="expryy"

%{
#include <stdlib.h>
#include <string.h>

#include "expr_ast.h"
#include "expr_parser.h"

static char *dup_text(void)
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
ID0     [A-Za-z_]
ID      [A-Za-z_][A-Za-z0-9_]*

%%

{WS}                ;
{EOL}               return T_EOL;
<<EOF>>             return 0;

"->"                return T_ARROW;
"<<"                return T_SHL;
">>"                return T_SHR;
"<="                return T_LE;
">="                return T_GE;
"=="                return T_EQ;
"!="                return T_NE;
"&&"                return T_LAND;
"||"                return T_LOR;

"$"{ID}             { expryylval.str = dup_text(); return T_REG; }

0[xX][0-9a-fA-F]+   { expryylval.u64 = strtoul(yytext, NULL, 0); return T_NUM; }
0[0-7]+             { expryylval.u64 = strtoul(yytext, NULL, 0); return T_NUM; }
[0-9]+              { expryylval.u64 = strtoul(yytext, NULL, 0); return T_NUM; }

{ID}                { expryylval.str = dup_text(); return T_IDENT; }

.                   { return (int)yytext[0]; }

%%

