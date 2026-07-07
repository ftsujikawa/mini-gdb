#include "dbg.h"
#include "expr_ast.h"
#include "expr_bison.h"

#include <stdlib.h>

typedef expr_bison_eval_result_t eval_result_t;
typedef expr_bison_c_expr_t c_expr_t;

static const char *skip_spaces(const char *p)
{
    while (*p == ' ' || *p == '\t')
        p++;
    return p;
}

static int reg_name_equal(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return 0;
        a++;
        b++;
    }
    return *a == *b;
}

typedef struct {
    const char *name;
    size_t offset;
} reg_info_t;

static int lookup_register(const char *name, const reg_info_t **info_out)
{
    static const reg_info_t regs[] = {
        { "rip", offsetof(struct user_regs_struct, rip) },
        { "pc",  offsetof(struct user_regs_struct, rip) },
        { "eip", offsetof(struct user_regs_struct, rip) },
        { "rsp", offsetof(struct user_regs_struct, rsp) },
        { "sp",  offsetof(struct user_regs_struct, rsp) },
        { "rbp", offsetof(struct user_regs_struct, rbp) },
        { "bp",  offsetof(struct user_regs_struct, rbp) },
        { "rax", offsetof(struct user_regs_struct, rax) },
        { "rbx", offsetof(struct user_regs_struct, rbx) },
        { "rcx", offsetof(struct user_regs_struct, rcx) },
        { "rdx", offsetof(struct user_regs_struct, rdx) },
        { "rsi", offsetof(struct user_regs_struct, rsi) },
        { "rdi", offsetof(struct user_regs_struct, rdi) },
        { "r8",  offsetof(struct user_regs_struct, r8) },
        { "r9",  offsetof(struct user_regs_struct, r9) },
        { "r10", offsetof(struct user_regs_struct, r10) },
        { "r11", offsetof(struct user_regs_struct, r11) },
        { "r12", offsetof(struct user_regs_struct, r12) },
        { "r13", offsetof(struct user_regs_struct, r13) },
        { "r14", offsetof(struct user_regs_struct, r14) },
        { "r15", offsetof(struct user_regs_struct, r15) },
        { "eflags", offsetof(struct user_regs_struct, eflags) },
    };

    if (*name == '$')
        name++;

    for (size_t i = 0; i < sizeof(regs) / sizeof(regs[0]); i++) {
        if (reg_name_equal(name, regs[i].name)) {
            *info_out = &regs[i];
            return 0;
        }
    }
    return -1;
}

static int read_var_addr(const char *name,
                         unsigned long rip,
                         unsigned long *addr_out,
                         uint32_t *type_off_out)
{
    var_entry_t *v = lookup_var(name, rip);
    if (v) {
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs);

        if (v->loc == VAR_FBREG)
            *addr_out = regs.rbp + 16 + v->fbreg;
        else
            *addr_out = to_runtime_addr(v->addr);
        *type_off_out = v->type_off;
        return 0;
    }

    for (int i = 0; i < sym_count; i++) {
        if (symbols[i].type != STT_OBJECT)
            continue;
        if (!strcmp(symbols[i].name, name)) {
            *addr_out = to_runtime_addr(symbols[i].addr);
            *type_off_out = 0;
            return 0;
        }
    }
    return -1;
}

static int read_typed_value(unsigned long addr,
                            const type_info_t *ti,
                            unsigned long *value_out)
{
    type_info_t resolved = *ti;
    uint32_t orig = 0;
    resolve_type_alias(&resolved, &orig);

    if (resolved.kind == TYPE_POINTER) {
        if (peek_word(addr, value_out) != 0)
            return -1;
        return 0;
    }

    if (resolved.kind != TYPE_BASE)
        return -1;

    long word = read_memory(addr);
    if (word == -1)
        return -1;

    if (resolved.size <= 1)
        *value_out = (unsigned long)(word & 0xff);
    else if (resolved.size <= 2)
        *value_out = (unsigned long)(word & 0xffff);
    else if (resolved.size <= 4)
        *value_out = (unsigned long)(uint32_t)word;
    else
        *value_out = (unsigned long)word;

    return 0;
}

static int is_aggregate_lval(const eval_result_t *res)
{
    type_info_t ti;
    if (!res->type_off || get_cached_type(res->type_off, &ti) != 0)
        return 0;
    resolve_type_alias(&ti, NULL);
    return ti.kind == TYPE_STRUCT || ti.kind == TYPE_ARRAY;
}

static int load_scalar(c_expr_t *out)
{
    if (!out->has_lval)
        return 0;
    if (is_aggregate_lval(&out->lval))
        return 0;

    type_info_t ti = { .kind = TYPE_BASE, .size = 4, .encoding = DW_ATE_signed };
    if (out->lval.type_off != 0)
        get_cached_type(out->lval.type_off, &ti);

    unsigned long uval;
    if (read_typed_value(out->lval.addr, &ti, &uval) != 0)
        return -1;
    out->value = (long)uval;
    return 0;
}

static int apply_deref(eval_result_t *res, int update_label)
{
    type_info_t ti;
    if (get_cached_type(res->type_off, &ti) != 0)
        return -1;
    resolve_type_alias(&ti, &res->type_off);
    if (ti.kind != TYPE_POINTER) {
        printf("cannot dereference non-pointer: %s\n", res->label);
        return -1;
    }
    unsigned long ptr;
    if (peek_word(res->addr, &ptr) != 0)
        return -1;

    if (update_label) {
        size_t len = strlen(res->label);
        if (len + 1 >= sizeof(res->label))
            len = sizeof(res->label) - 2;
        memmove(res->label + 1, res->label, len + 1);
        res->label[0] = '*';
    }

    res->addr = ptr;
    res->type_off = ti.ref_off;
    return 0;
}

static int resolve_member(eval_result_t *res, const char *member)
{
    type_info_t ti;
    if (get_cached_type(res->type_off, &ti) != 0)
        return -1;
    resolve_type_alias(&ti, &res->type_off);
    if (ti.kind != TYPE_STRUCT) {
        printf("not a struct: %s\n", res->label);
        return -1;
    }
    for (int i = 0; i < ti.member_count; i++) {
        if (!strcmp(ti.members[i].name, member)) {
            res->addr += (unsigned long)ti.members[i].offset;
            res->type_off = ti.members[i].type_off;
            return 0;
        }
    }
    printf("no member '%s' in %s\n", member, res->label);
    return -1;
}

static void append_label(char *label, size_t labelsz, const char *suffix)
{
    size_t cur = strlen(label);
    if (cur + 1 >= labelsz)
        return;
    strncat(label, suffix, labelsz - cur - 1);
}

static int apply_member(eval_result_t *res, const char *member, int is_ptr)
{
    if (is_ptr) {
        char base_label[256];
        strncpy(base_label, res->label, sizeof(base_label) - 1);
        base_label[sizeof(base_label) - 1] = '\0';

        if (apply_deref(res, 0) != 0)
            return -1;
        if (resolve_member(res, member) != 0)
            return -1;

        strncpy(res->label, base_label, sizeof(res->label) - 1);
        res->label[sizeof(res->label) - 1] = '\0';
        append_label(res->label, sizeof(res->label), "->");
        append_label(res->label, sizeof(res->label), member);
        return 0;
    }

    type_info_t ti;
    if (get_cached_type(res->type_off, &ti) == 0) {
        resolve_type_alias(&ti, &res->type_off);
        if (ti.kind == TYPE_POINTER && apply_deref(res, 0) != 0)
            return -1;
    }
    if (resolve_member(res, member) != 0)
        return -1;
    append_label(res->label, sizeof(res->label), ".");
    append_label(res->label, sizeof(res->label), member);
    return 0;
}

static int apply_index(eval_result_t *res, long index)
{
    type_info_t ti;
    if (get_cached_type(res->type_off, &ti) != 0)
        return -1;
    resolve_type_alias(&ti, &res->type_off);
    if (ti.kind != TYPE_ARRAY) {
        printf("not an array: %s\n", res->label);
        return -1;
    }
    if (index < 0 || index >= ti.array_count) {
        printf("index %ld out of range for %s\n", index, res->label);
        return -1;
    }

    type_info_t elem;
    if (get_cached_type(ti.elem_type_off, &elem) != 0)
        return -1;
    resolve_type_alias(&elem, &res->type_off);

    res->addr += (unsigned long)(index * (long)elem.size);
    res->type_off = ti.elem_type_off;

    char idx[32];
    snprintf(idx, sizeof(idx), "[%ld]", index);
    append_label(res->label, sizeof(res->label), idx);
    return 0;
}

static int require_scalar(c_expr_t *n)
{
    if (n->has_lval && is_aggregate_lval(&n->lval)) {
        printf("aggregate value in expression: %s\n", n->lval.label);
        return -1;
    }

    if (n->has_lval && load_scalar(n) != 0)
        return -1;

    n->has_lval = 0;
    return 0;
}

static int eval_ast(const expr_ast_t *n, unsigned long rip, c_expr_t *out);

static int expr_to_ulong(const c_expr_t *node, unsigned long *out)
{
    if (node->has_lval) {
        type_info_t ti = { .kind = TYPE_BASE, .size = 4, .encoding = DW_ATE_signed };
        if (node->lval.type_off && get_cached_type(node->lval.type_off, &ti) != 0)
            return -1;
        return read_typed_value(node->lval.addr, &ti, out);
    }
    *out = (unsigned long)node->value;
    return 0;
}

static int eval_primary_ident(const char *name, unsigned long rip, c_expr_t *out)
{
    eval_result_t res;
    if (read_var_addr(name, rip, &res.addr, &res.type_off) != 0) {
        printf("unknown variable: %s\n", name);
        return -1;
    }
    strncpy(res.label, name, sizeof(res.label) - 1);
    res.label[sizeof(res.label) - 1] = '\0';
    out->has_lval = 1;
    out->lval = res;
    if (is_aggregate_lval(&res))
        return 0;
    return load_scalar(out);
}

static int eval_primary_reg(const char *name, c_expr_t *out)
{
    const reg_info_t *reg;
    if (lookup_register(name, &reg) != 0) {
        printf("unknown register: %s\n", name);
        return -1;
    }
    if (!dbg.running) {
        printf("no process\n");
        return -1;
    }
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs) == -1) {
        perror("ptrace getregs");
        return -1;
    }
    out->value = (long)*(unsigned long long *)((char *)&regs + reg->offset);
    out->has_lval = 0;
    return 0;
}

static int eval_ast(const expr_ast_t *n, unsigned long rip, c_expr_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!n) {
        printf("syntax error\n");
        return -1;
    }

    switch (n->kind) {
    case EXPR_NUM:
        out->value = (long)n->as.num;
        out->has_lval = 0;
        return 0;
    case EXPR_IDENT:
        return eval_primary_ident(n->as.str, rip, out);
    case EXPR_REG:
        return eval_primary_reg(n->as.str, out);
    case EXPR_MEMBER:
    case EXPR_PTR_MEMBER: {
        c_expr_t base;
        if (eval_ast(n->as.member.base, rip, &base) != 0)
            return -1;
        if (!base.has_lval) {
            printf("not an lvalue\n");
            return -1;
        }
        eval_result_t res = base.lval;
        if (apply_member(&res, n->as.member.member,
                         n->kind == EXPR_PTR_MEMBER) != 0)
            return -1;
        out->has_lval = 1;
        out->lval = res;
        if (is_aggregate_lval(&res))
            return 0;
        return load_scalar(out);
    }
    case EXPR_INDEX: {
        c_expr_t base, idx;
        if (eval_ast(n->as.index.base, rip, &base) != 0)
            return -1;
        if (eval_ast(n->as.index.idx, rip, &idx) != 0)
            return -1;
        if (!base.has_lval) {
            printf("not an lvalue\n");
            return -1;
        }
        if (require_scalar(&idx) != 0)
            return -1;
        eval_result_t res = base.lval;
        if (apply_index(&res, idx.value) != 0)
            return -1;
        out->has_lval = 1;
        out->lval = res;
        if (is_aggregate_lval(&res))
            return 0;
        return load_scalar(out);
    }
    case EXPR_UNARY: {
        c_expr_t x;
        if (eval_ast(n->as.unary.x, rip, &x) != 0)
            return -1;
        switch (n->as.unary.op) {
        case UOP_POS:
            if (require_scalar(&x) != 0)
                return -1;
            *out = x;
            return 0;
        case UOP_NEG:
            if (require_scalar(&x) != 0)
                return -1;
            out->value = -x.value;
            out->has_lval = 0;
            return 0;
        case UOP_BNOT:
            if (require_scalar(&x) != 0)
                return -1;
            out->value = ~x.value;
            out->has_lval = 0;
            return 0;
        case UOP_LNOT:
            if (require_scalar(&x) != 0)
                return -1;
            out->value = !x.value;
            out->has_lval = 0;
            return 0;
        case UOP_ADDR:
            if (!x.has_lval) {
                printf("invalid address-of operand\n");
                return -1;
            }
            out->value = (long)x.lval.addr;
            out->has_lval = 0;
            out->rvalue_type_off = lookup_pointer_type(x.lval.type_off);
            return 0;
        case UOP_DEREF:
            if (!x.has_lval) {
                printf("invalid dereference\n");
                return -1;
            }
            if (apply_deref(&x.lval, 1) != 0)
                return -1;
            out->has_lval = 1;
            out->lval = x.lval;
            if (is_aggregate_lval(&out->lval))
                return 0;
            return load_scalar(out);
        default:
            return -1;
        }
    }
    case EXPR_BINARY: {
        c_expr_t l, r;
        if (eval_ast(n->as.bin.l, rip, &l) != 0)
            return -1;
        if (eval_ast(n->as.bin.r, rip, &r) != 0)
            return -1;
        if (require_scalar(&l) != 0 || require_scalar(&r) != 0)
            return -1;

        long lv = l.value;
        long rv = r.value;
        long res = 0;

        switch (n->as.bin.op) {
        case BOP_MUL:  res = lv * rv; break;
        case BOP_DIV:
            if (rv == 0) { printf("division by zero\n"); return -1; }
            res = lv / rv; break;
        case BOP_MOD:
            if (rv == 0) { printf("division by zero\n"); return -1; }
            res = lv % rv; break;
        case BOP_ADD:  res = lv + rv; break;
        case BOP_SUB:  res = lv - rv; break;
        case BOP_SHL:  res = (long)((unsigned long)lv << (unsigned)(rv & 63)); break;
        case BOP_SHR:  res = (long)((unsigned long)lv >> (unsigned)(rv & 63)); break;
        case BOP_LT:   res = (lv <  rv) ? 1 : 0; break;
        case BOP_LE:   res = (lv <= rv) ? 1 : 0; break;
        case BOP_GT:   res = (lv >  rv) ? 1 : 0; break;
        case BOP_GE:   res = (lv >= rv) ? 1 : 0; break;
        case BOP_EQ:   res = (lv == rv) ? 1 : 0; break;
        case BOP_NE:   res = (lv != rv) ? 1 : 0; break;
        case BOP_BAND: res = (long)((unsigned long)lv & (unsigned long)rv); break;
        case BOP_BXOR: res = (long)((unsigned long)lv ^ (unsigned long)rv); break;
        case BOP_BOR:  res = (long)((unsigned long)lv | (unsigned long)rv); break;
        case BOP_LAND: res = (lv && rv) ? 1 : 0; break;
        case BOP_LOR:  res = (lv || rv) ? 1 : 0; break;
        default:
            return -1;
        }

        out->value = res;
        out->has_lval = 0;
        return 0;
    }
    default:
        return -1;
    }
}

/* Exported entry used by expr.c when flex/bison are available */
int eval_expression_bison(const char *expr, unsigned long rip, c_expr_t *out)
{
    char err[256];
    expr_ast_t *ast = NULL;

    const char *p = skip_spaces(expr);
    if (!*p) {
        printf("syntax error\n");
        return -1;
    }

    if (expr_parse_ast(p, &ast, err, sizeof(err)) != 0) {
        printf("%s\n", err[0] ? err : "syntax error");
        return -1;
    }

    int rc = eval_ast(ast, rip, out);
    expr_ast_free(ast);
    return rc;
}

int eval_lvalue_bison(const char *expr, unsigned long rip, eval_result_t *res)
{
    c_expr_t n;
    if (eval_expression_bison(expr, rip, &n) != 0)
        return -1;
    if (!n.has_lval) {
        printf("not an lvalue: %s\n", expr);
        return -1;
    }
    *res = n.lval;
    return 0;
}

int expr_to_ulong_bison(const c_expr_t *node, unsigned long *out)
{
    return expr_to_ulong(node, out);
}

