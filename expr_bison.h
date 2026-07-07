#ifndef EXPR_BISON_H
#define EXPR_BISON_H

#include <stddef.h>

#include "expr_ast.h"

int expr_parse_ast(const char *expr, expr_ast_t **out_ast,
                   char *errbuf, size_t errbufsz);

#endif

