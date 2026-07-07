%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "expr_ast.h"
#include "expr_bison.h"

/* parser output */
expr_ast_t *expr_parsed_ast = NULL;
char expr_parse_error[256] = {0};

static void set_ast(expr_ast_t *n) { expr_parsed_ast = n; }

int expryylex(void);
void expryyerror(const char *s);
%}

%define api.prefix {expryy}

%union {
    unsigned long u64;
    char *str;
    expr_ast_t *ast;
}

%token T_EOL
%token <u64> T_NUM
%token <str> T_IDENT
%token <str> T_REG

%token T_SHL T_SHR
%token T_LE T_GE T_EQ T_NE
%token T_LAND T_LOR
%token T_ARROW

%type <ast> expr primary postfix

%left T_LOR
%left T_LAND
%left '|'
%left '^'
%left '&'
%left T_EQ T_NE
%left '<' '>' T_LE T_GE
%left T_SHL T_SHR
%left '+' '-'
%left '*' '/' '%'
%right UPLUS UMINUS '!' '~' DEREF ADDR

%%

input
  : expr opt_eol { set_ast($1); }
  | T_EOL        { set_ast(NULL); }
  ;

opt_eol
  : /* empty */
  | T_EOL
  ;

expr
  : expr T_LOR expr     { $$ = expr_ast_binary(BOP_LOR,  $1, $3); }
  | expr T_LAND expr    { $$ = expr_ast_binary(BOP_LAND, $1, $3); }
  | expr '|' expr       { $$ = expr_ast_binary(BOP_BOR,  $1, $3); }
  | expr '^' expr       { $$ = expr_ast_binary(BOP_BXOR, $1, $3); }
  | expr '&' expr       { $$ = expr_ast_binary(BOP_BAND, $1, $3); }
  | expr T_EQ expr      { $$ = expr_ast_binary(BOP_EQ,   $1, $3); }
  | expr T_NE expr      { $$ = expr_ast_binary(BOP_NE,   $1, $3); }
  | expr '<' expr       { $$ = expr_ast_binary(BOP_LT,   $1, $3); }
  | expr '>' expr       { $$ = expr_ast_binary(BOP_GT,   $1, $3); }
  | expr T_LE expr      { $$ = expr_ast_binary(BOP_LE,   $1, $3); }
  | expr T_GE expr      { $$ = expr_ast_binary(BOP_GE,   $1, $3); }
  | expr T_SHL expr     { $$ = expr_ast_binary(BOP_SHL,  $1, $3); }
  | expr T_SHR expr     { $$ = expr_ast_binary(BOP_SHR,  $1, $3); }
  | expr '+' expr       { $$ = expr_ast_binary(BOP_ADD,  $1, $3); }
  | expr '-' expr       { $$ = expr_ast_binary(BOP_SUB,  $1, $3); }
  | expr '*' expr       { $$ = expr_ast_binary(BOP_MUL,  $1, $3); }
  | expr '/' expr       { $$ = expr_ast_binary(BOP_DIV,  $1, $3); }
  | expr '%' expr       { $$ = expr_ast_binary(BOP_MOD,  $1, $3); }

  | '+' expr %prec UPLUS  { $$ = expr_ast_unary(UOP_POS, $2); }
  | '-' expr %prec UMINUS { $$ = expr_ast_unary(UOP_NEG, $2); }
  | '!' expr              { $$ = expr_ast_unary(UOP_LNOT, $2); }
  | '~' expr              { $$ = expr_ast_unary(UOP_BNOT, $2); }
  | '&' expr %prec ADDR   { $$ = expr_ast_unary(UOP_ADDR, $2); }
  | '*' expr %prec DEREF  { $$ = expr_ast_unary(UOP_DEREF, $2); }

  | postfix               { $$ = $1; }
  ;

postfix
  : primary                         { $$ = $1; }
  | postfix '.' T_IDENT             { $$ = expr_ast_member($1, $3, 0); }
  | postfix T_ARROW T_IDENT         { $$ = expr_ast_member($1, $3, 1); }
  | postfix '[' expr ']'            { $$ = expr_ast_index($1, $3); }
  ;

primary
  : T_NUM                           { $$ = expr_ast_num($1); }
  | T_IDENT                         { $$ = expr_ast_ident($1); }
  | T_REG                           { $$ = expr_ast_reg($1); }
  | '(' expr ')'                    { $$ = $2; }
  ;

%%

void expryyerror(const char *s)
{
    if (!expr_parse_error[0]) {
        snprintf(expr_parse_error, sizeof(expr_parse_error), "%s", s);
    }
}

