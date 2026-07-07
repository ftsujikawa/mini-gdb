#ifndef EXPR_AST_H
#define EXPR_AST_H

#include <stdint.h>

typedef enum {
    EXPR_NUM = 1,
    EXPR_IDENT,
    EXPR_REG,
    EXPR_UNARY,
    EXPR_BINARY,
    EXPR_MEMBER,      /* base.member */
    EXPR_PTR_MEMBER,  /* base->member */
    EXPR_INDEX,       /* base[idx] */
} expr_kind_t;

typedef enum {
    UOP_POS = 1,
    UOP_NEG,
    UOP_BNOT,
    UOP_LNOT,
    UOP_ADDR,
    UOP_DEREF,
} unary_op_t;

typedef enum {
    BOP_MUL = 1,
    BOP_DIV,
    BOP_MOD,
    BOP_ADD,
    BOP_SUB,
    BOP_SHL,
    BOP_SHR,
    BOP_LT,
    BOP_LE,
    BOP_GT,
    BOP_GE,
    BOP_EQ,
    BOP_NE,
    BOP_BAND,
    BOP_BXOR,
    BOP_BOR,
    BOP_LAND,
    BOP_LOR,
} binary_op_t;

typedef struct expr_ast expr_ast_t;

struct expr_ast {
    expr_kind_t kind;
    union {
        unsigned long num;
        char *str; /* ident/reg/member name */
        struct {
            unary_op_t op;
            expr_ast_t *x;
        } unary;
        struct {
            binary_op_t op;
            expr_ast_t *l;
            expr_ast_t *r;
        } bin;
        struct {
            expr_ast_t *base;
            char *member;
        } member;
        struct {
            expr_ast_t *base;
            expr_ast_t *idx;
        } index;
    } as;
};

expr_ast_t *expr_ast_num(unsigned long v);
expr_ast_t *expr_ast_ident(char *name); /* takes ownership */
expr_ast_t *expr_ast_reg(char *name);   /* takes ownership */
expr_ast_t *expr_ast_unary(unary_op_t op, expr_ast_t *x);
expr_ast_t *expr_ast_binary(binary_op_t op, expr_ast_t *l, expr_ast_t *r);
expr_ast_t *expr_ast_member(expr_ast_t *base, char *member, int is_ptr);
expr_ast_t *expr_ast_index(expr_ast_t *base, expr_ast_t *idx);

void expr_ast_free(expr_ast_t *n);

#endif

