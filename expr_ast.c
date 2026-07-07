#include "expr_ast.h"

#include <stdlib.h>

static expr_ast_t *node(expr_kind_t k)
{
    expr_ast_t *n = (expr_ast_t *)calloc(1, sizeof(*n));
    if (n)
        n->kind = k;
    return n;
}

expr_ast_t *expr_ast_num(unsigned long v)
{
    expr_ast_t *n = node(EXPR_NUM);
    if (n)
        n->as.num = v;
    return n;
}

expr_ast_t *expr_ast_ident(char *name)
{
    expr_ast_t *n = node(EXPR_IDENT);
    if (!n) {
        free(name);
        return NULL;
    }
    n->as.str = name;
    return n;
}

expr_ast_t *expr_ast_reg(char *name)
{
    expr_ast_t *n = node(EXPR_REG);
    if (!n) {
        free(name);
        return NULL;
    }
    n->as.str = name;
    return n;
}

expr_ast_t *expr_ast_unary(unary_op_t op, expr_ast_t *x)
{
    expr_ast_t *n = node(EXPR_UNARY);
    if (!n) {
        expr_ast_free(x);
        return NULL;
    }
    n->as.unary.op = op;
    n->as.unary.x = x;
    return n;
}

expr_ast_t *expr_ast_binary(binary_op_t op, expr_ast_t *l, expr_ast_t *r)
{
    expr_ast_t *n = node(EXPR_BINARY);
    if (!n) {
        expr_ast_free(l);
        expr_ast_free(r);
        return NULL;
    }
    n->as.bin.op = op;
    n->as.bin.l = l;
    n->as.bin.r = r;
    return n;
}

expr_ast_t *expr_ast_member(expr_ast_t *base, char *member, int is_ptr)
{
    expr_ast_t *n = node(is_ptr ? EXPR_PTR_MEMBER : EXPR_MEMBER);
    if (!n) {
        expr_ast_free(base);
        free(member);
        return NULL;
    }
    n->as.member.base = base;
    n->as.member.member = member;
    return n;
}

expr_ast_t *expr_ast_index(expr_ast_t *base, expr_ast_t *idx)
{
    expr_ast_t *n = node(EXPR_INDEX);
    if (!n) {
        expr_ast_free(base);
        expr_ast_free(idx);
        return NULL;
    }
    n->as.index.base = base;
    n->as.index.idx = idx;
    return n;
}

void expr_ast_free(expr_ast_t *n)
{
    if (!n)
        return;
    switch (n->kind) {
    case EXPR_NUM:
        break;
    case EXPR_IDENT:
    case EXPR_REG:
        free(n->as.str);
        break;
    case EXPR_UNARY:
        expr_ast_free(n->as.unary.x);
        break;
    case EXPR_BINARY:
        expr_ast_free(n->as.bin.l);
        expr_ast_free(n->as.bin.r);
        break;
    case EXPR_MEMBER:
    case EXPR_PTR_MEMBER:
        expr_ast_free(n->as.member.base);
        free(n->as.member.member);
        break;
    case EXPR_INDEX:
        expr_ast_free(n->as.index.base);
        expr_ast_free(n->as.index.idx);
        break;
    default:
        break;
    }
    free(n);
}

