#include "expr_bison.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* bison/flex interface (generated with %define api.prefix {expryy}) */
int expryyparse(void);
void expryyrestart(FILE *input_file);
typedef struct yy_buffer_state *YY_BUFFER_STATE;
YY_BUFFER_STATE expryy_scan_string(const char *yy_str);
void expryy_delete_buffer(YY_BUFFER_STATE b);

extern expr_ast_t *expr_parsed_ast;
extern char expr_parse_error[256];

int expr_parse_ast(const char *expr, expr_ast_t **out_ast,
                   char *errbuf, size_t errbufsz)
{
    if (out_ast)
        *out_ast = NULL;

    expr_ast_free(expr_parsed_ast);
    expr_parsed_ast = NULL;
    expr_parse_error[0] = '\0';

    YY_BUFFER_STATE buf = expryy_scan_string(expr ? expr : "");

    int rc = expryyparse();

    expryy_delete_buffer(buf);

    if (rc != 0) {
        if (errbuf && errbufsz) {
            snprintf(errbuf, errbufsz, "%s",
                     expr_parse_error[0] ? expr_parse_error : "parse error");
        }
        expr_ast_free(expr_parsed_ast);
        expr_parsed_ast = NULL;
        return -1;
    }

    if (out_ast)
        *out_ast = expr_parsed_ast;
    expr_parsed_ast = NULL;

    if (errbuf && errbufsz)
        errbuf[0] = '\0';

    return 0;
}

