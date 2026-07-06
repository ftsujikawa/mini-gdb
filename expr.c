#include "dbg.h"

typedef enum {
    PRINT_FMT_DEFAULT = -1,
    PRINT_FMT_DECIMAL,
    PRINT_FMT_HEX,
    PRINT_FMT_OCTAL,
    PRINT_FMT_BINARY,
    PRINT_FMT_UNSIGNED,
    PRINT_FMT_CHAR,
    PRINT_FMT_STRING,
    PRINT_FMT_POINTER,
} print_format_t;

typedef enum {
    LANG_C,
} language_t;

typedef struct {
    language_t language;
    print_format_t format;
    int print_array;
    int print_pretty;
    int print_elements;
} print_settings_t;

static print_settings_t print_settings = {
    .language = LANG_C,
    .format = PRINT_FMT_DECIMAL,
    .print_array = 1,
    .print_pretty = 0,
    .print_elements = -1,
};

static const char *format_name(print_format_t fmt)
{
    switch (fmt) {
    case PRINT_FMT_HEX:      return "hex";
    case PRINT_FMT_OCTAL:    return "octal";
    case PRINT_FMT_BINARY:   return "binary";
    case PRINT_FMT_UNSIGNED: return "unsigned";
    case PRINT_FMT_CHAR:     return "char";
    case PRINT_FMT_STRING:   return "string";
    case PRINT_FMT_POINTER:  return "pointer";
    case PRINT_FMT_DECIMAL:
    default:                 return "decimal";
    }
}

static print_format_t parse_format_name(const char *name)
{
    if (!strcmp(name, "dec") || !strcmp(name, "decimal") ||
        !strcmp(name, "signed"))
        return PRINT_FMT_DECIMAL;

    if (!strcmp(name, "hex"))
        return PRINT_FMT_HEX;

    if (!strcmp(name, "oct") || !strcmp(name, "octal"))
        return PRINT_FMT_OCTAL;

    if (!strcmp(name, "bin") || !strcmp(name, "binary"))
        return PRINT_FMT_BINARY;

    if (!strcmp(name, "unsigned"))
        return PRINT_FMT_UNSIGNED;

    if (!strcmp(name, "char"))
        return PRINT_FMT_CHAR;

    if (!strcmp(name, "string"))
        return PRINT_FMT_STRING;

    if (!strcmp(name, "pointer") || !strcmp(name, "addr"))
        return PRINT_FMT_POINTER;

    return PRINT_FMT_DEFAULT;
}

static void show_print_settings(void)
{
    printf("Language: C\n");
    printf("Print format: %s\n", format_name(print_settings.format));
    printf("Output radix: ");

    switch (print_settings.format) {
    case PRINT_FMT_OCTAL:
        printf("8\n");
        break;
    case PRINT_FMT_HEX:
        printf("16\n");
        break;
    case PRINT_FMT_BINARY:
        printf("2\n");
        break;
    default:
        printf("10\n");
        break;
    }

    printf("Print array: %s\n",
           print_settings.print_array ? "on" : "off");
    printf("Print pretty: %s\n",
           print_settings.print_pretty ? "on" : "off");

    if (print_settings.print_elements < 0)
        printf("Print elements: unlimited\n");
    else
        printf("Print elements: %d\n", print_settings.print_elements);
}

#define MAX_PRINT_STRING 256

static void print_string_value(const char *label, unsigned long addr)
{
    printf("%s = \"", label);

    for (int i = 0; i < MAX_PRINT_STRING; i++) {
        unsigned char c;

        if (read_target_byte(addr + (unsigned long)i, &c) != 0) {
            printf("<error>");
            break;
        }

        if (c == '\0')
            break;

        if (c >= 32 && c <= 126)
            putchar(c);
        else if (c == '\n')
            printf("\\n");
        else if (c == '\t')
            printf("\\t");
        else if (c == '\\')
            printf("\\\\");
        else if (c == '"')
            printf("\\\"");
        else
            printf("\\x%02x", c);
    }

    printf("\"\n");
}

static unsigned long resolve_string_addr(unsigned long addr, uint32_t type_off)
{
    type_info_t ti;

    if (type_off == 0 || get_cached_type(type_off, &ti) != 0)
        return addr;

    resolve_type_alias(&ti, NULL);

    if (ti.kind == TYPE_POINTER) {
        unsigned long ptr;

        if (peek_word(addr, &ptr) == 0)
            return ptr;
    }

    if (ti.kind == TYPE_ARRAY) {
        type_info_t elem;

        if (get_cached_type(ti.elem_type_off, &elem) == 0) {
            resolve_type_alias(&elem, NULL);

            if (elem.kind == TYPE_BASE && elem.size == 1)
                return addr;
        }
    }

    return addr;
}

static void print_value(const char *label,
                        unsigned long value,
                        print_format_t fmt)
{
    if (fmt == PRINT_FMT_DEFAULT)
        fmt = print_settings.format;

    switch (fmt) {
    case PRINT_FMT_HEX:
        printf("%s = 0x%lx\n", label, value);
        break;
    case PRINT_FMT_OCTAL:
        printf("%s = %#lo\n", label, value);
        break;
    case PRINT_FMT_BINARY: {
        printf("%s = 0b", label);
        int started = 0;

        for (int i = 63; i >= 0; i--) {
            int bit = (value >> i) & 1;

            if (bit)
                started = 1;

            if (started || i == 0)
                putchar(bit ? '1' : '0');
        }

        putchar('\n');
        break;
    }
    case PRINT_FMT_UNSIGNED:
        printf("%s = %lu\n", label, value);
        break;
    case PRINT_FMT_CHAR: {
        unsigned char c = (unsigned char)value;

        if (c >= 32 && c <= 126)
            printf("%s = '%c'\n", label, (char)c);
        else
            printf("%s = '\\x%02x'\n", label, c);
        break;
    }
    case PRINT_FMT_STRING:
        print_string_value(label, value);
        break;
    case PRINT_FMT_POINTER:
        printf("%s = %p\n", label, (void *)value);
        break;
    case PRINT_FMT_DECIMAL:
    default:
        printf("%s = %ld\n", label, (long)value);
        break;
    }
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

static int write_typed_value(unsigned long addr,
                             const type_info_t *ti,
                             unsigned long value)
{
    type_info_t resolved = *ti;
    uint32_t orig = 0;

    resolve_type_alias(&resolved, &orig);

    if (resolved.kind != TYPE_BASE &&
        resolved.kind != TYPE_POINTER) {
        printf("cannot assign to aggregate type\n");
        return -1;
    }

    size_t size = resolved.size;

    if (resolved.kind == TYPE_POINTER)
        size = dwarf_addr_size;

    if (size == 0)
        size = 4;

    long word = read_memory(addr);

    if (word == -1)
        return -1;

    unsigned long mask;

    if (size <= 1)
        mask = 0xff;
    else if (size <= 2)
        mask = 0xffff;
    else if (size <= 4)
        mask = 0xffffffffUL;
    else
        mask = ~0UL;

    long patched = (word & ~(long)mask) | (long)(value & mask);

    return poke_word(addr, (unsigned long)patched);
}

static void append_label(char *label, size_t labelsz, const char *suffix)
{
    size_t cur = strlen(label);

    if (cur + 1 >= labelsz)
        return;

    strncat(label, suffix, labelsz - cur - 1);
}

static const char *skip_spaces(const char *p)
{
    while (*p == ' ' || *p == '\t')
        p++;

    return p;
}

static const char *parse_c_ident(const char *p, char *out, size_t outsz)
{
    size_t i = 0;

    if (!((*p >= 'a' && *p <= 'z') ||
          (*p >= 'A' && *p <= 'Z') || *p == '_'))
        return NULL;

    while ((*p >= 'a' && *p <= 'z') ||
           (*p >= 'A' && *p <= 'Z') ||
           (*p >= '0' && *p <= '9') || *p == '_') {
        if (i + 1 < outsz)
            out[i++] = *p;
        p++;
    }

    out[i] = '\0';
    return p;
}

typedef struct {
    unsigned long addr;
    uint32_t type_off;
    char label[256];
} eval_result_t;

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

static int apply_member(eval_result_t *res, const char *member)
{
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

static void print_struct_members_inline(unsigned long addr,
                                        const type_info_t *ti)
{
    if (print_settings.print_pretty) {
        printf("{\n");

        for (int i = 0; i < ti->member_count; i++) {
            type_info_t mt;

            if (get_cached_type(ti->members[i].type_off, &mt) != 0)
                continue;

            resolve_type_alias(&mt, NULL);

            unsigned long mval;

            if (read_typed_value(addr + (unsigned long)ti->members[i].offset,
                                 &mt, &mval) != 0)
                continue;

            printf("  %s = ", ti->members[i].name);

            if (mt.kind == TYPE_POINTER)
                printf("%p", (void *)mval);
            else if (mt.encoding == DW_ATE_unsigned)
                printf("%lu", mval);
            else
                printf("%ld", (long)mval);

            if (i + 1 < ti->member_count)
                putchar(',');

            putchar('\n');
        }

        printf("}");
        return;
    }

    printf("{");

    for (int i = 0; i < ti->member_count; i++) {
        type_info_t mt;

        if (get_cached_type(ti->members[i].type_off, &mt) != 0)
            continue;

        resolve_type_alias(&mt, NULL);

        unsigned long mval;

        if (read_typed_value(addr + (unsigned long)ti->members[i].offset,
                             &mt, &mval) != 0)
            continue;

        if (i > 0)
            printf(", ");

        printf("%s = ", ti->members[i].name);

        if (mt.kind == TYPE_POINTER)
            printf("%p", (void *)mval);
        else if (mt.encoding == DW_ATE_unsigned)
            printf("%lu", mval);
        else
            printf("%ld", (long)mval);
    }

    printf("}");
}

static void print_struct_value(const char *label,
                               unsigned long addr,
                               const type_info_t *ti,
                               print_format_t fmt)
{
    if (label[0])
        printf("%s = ", label);

    print_struct_members_inline(addr, ti);
    putchar('\n');
    (void)fmt;
}

static void print_array_value(const char *label,
                              unsigned long addr,
                              const type_info_t *ti,
                              print_format_t fmt)
{
    if (!print_settings.print_array) {
        print_value(label, addr, PRINT_FMT_POINTER);
        return;
    }

    type_info_t elem;

    if (get_cached_type(ti->elem_type_off, &elem) != 0) {
        printf("%s = <array>\n", label);
        return;
    }

    resolve_type_alias(&elem, NULL);

    int count = ti->array_count;

    if (print_settings.print_elements >= 0 &&
        count > print_settings.print_elements)
        count = print_settings.print_elements;

    printf("%s = {", label);

    for (int i = 0; i < count; i++) {
        unsigned long elem_addr =
            addr + (unsigned long)(i * (long)elem.size);

        if (elem.kind == TYPE_STRUCT) {
            if (i > 0)
                printf(", ");
            print_struct_members_inline(elem_addr, &elem);
        } else {
            unsigned long val;

            if (read_typed_value(elem_addr, &elem, &val) != 0)
                continue;

            if (i > 0)
                printf(", ");

            if (elem.kind == TYPE_POINTER)
                printf("%p", (void *)val);
            else if (elem.encoding == DW_ATE_unsigned)
                printf("%lu", val);
            else
                printf("%ld", (long)val);
        }
    }

    if (print_settings.print_elements >= 0 &&
        ti->array_count > print_settings.print_elements)
        printf(", ...");

    printf("}\n");
    (void)fmt;
}

static void print_eval_result(const eval_result_t *res, print_format_t fmt)
{
    type_info_t ti;

    if (fmt == PRINT_FMT_STRING) {
        unsigned long str_addr =
            resolve_string_addr(res->addr, res->type_off);

        print_string_value(res->label, str_addr);
        return;
    }

    if (res->type_off == 0 ||
        get_cached_type(res->type_off, &ti) != 0) {
        unsigned long val;

        if (peek_word(res->addr, &val) != 0)
            return;

        print_value(res->label, val, fmt);
        return;
    }

    resolve_type_alias(&ti, NULL);

    if (ti.kind == TYPE_STRUCT) {
        print_struct_value(res->label, res->addr, &ti, fmt);
        return;
    }

    if (ti.kind == TYPE_ARRAY) {
        print_array_value(res->label, res->addr, &ti, fmt);
        return;
    }

    unsigned long val;

    if (read_typed_value(res->addr, &ti, &val) != 0)
        return;

    if (ti.kind == TYPE_POINTER &&
        fmt == PRINT_FMT_DEFAULT)
        fmt = PRINT_FMT_POINTER;

    print_value(res->label, val, fmt);
}

typedef struct {
    const char *name;
    size_t offset;
} reg_info_t;

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

typedef struct {
    const char *cur;
    unsigned long rip;
} ep_t;

typedef struct {
    long value;
    int has_lval;
    eval_result_t lval;
} c_expr_t;

static int ep_parse_register(ep_t *ep, c_expr_t *out)
{
    const reg_info_t *reg;
    char name[64];

    if (*ep->cur != '$')
        return 0;

    ep->cur++;

    ep->cur = parse_c_ident(ep->cur, name, sizeof(name));

    if (!name[0]) {
        printf("expected register name\n");
        return -1;
    }

    if (lookup_register(name, &reg) != 0) {
        printf("unknown register: $%s\n", name);
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

    out->value =
        (long)*(unsigned long long *)((char *)&regs + reg->offset);
    out->has_lval = 0;
    return 1;
}

static int ep_is_ident_start(char c)
{
    return (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') || c == '_';
}

static int ep_is_binop_at(const char *p)
{
    p = skip_spaces(p);

    if (*p == '\0' || *p == ')' || *p == ']' || *p == '=')
        return 0;

    if (*p == '-' && p[1] == '>')
        return 0;

    if (!strncmp(p, "||", 2) || !strncmp(p, "&&", 2) ||
        !strncmp(p, "==", 2) || !strncmp(p, "!=", 2) ||
        !strncmp(p, "<=", 2) || !strncmp(p, ">=", 2) ||
        !strncmp(p, "<<", 2) || !strncmp(p, ">>", 2))
        return 1;

    return strchr("+-*/%&|^<>!", *p) != NULL;
}

static int ep_is_aggregate_lval(const eval_result_t *res)
{
    type_info_t ti;

    if (!res->type_off || get_cached_type(res->type_off, &ti) != 0)
        return 0;

    resolve_type_alias(&ti, NULL);

    return ti.kind == TYPE_STRUCT || ti.kind == TYPE_ARRAY;
}

static int ep_load_scalar(c_expr_t *out)
{
    if (!out->has_lval)
        return 0;

    if (ep_is_aggregate_lval(&out->lval))
        return 0;

    type_info_t ti = {
        .kind = TYPE_BASE,
        .size = 4,
        .encoding = DW_ATE_signed,
    };

    if (out->lval.type_off != 0)
        get_cached_type(out->lval.type_off, &ti);

    unsigned long uval;

    if (read_typed_value(out->lval.addr, &ti, &uval) != 0)
        return -1;

    out->value = (long)uval;
    return 0;
}

static int ep_parse_or(ep_t *ep, c_expr_t *out);
static int ep_parse_primary(ep_t *ep, c_expr_t *out);
static int ep_parse_unary(ep_t *ep, c_expr_t *out);
static int ep_parse_mul(ep_t *ep, c_expr_t *out);
static int ep_parse_add(ep_t *ep, c_expr_t *out);
static int ep_parse_shift(ep_t *ep, c_expr_t *out);
static int ep_parse_rel(ep_t *ep, c_expr_t *out);
static int ep_parse_eq(ep_t *ep, c_expr_t *out);
static int ep_parse_bitand(ep_t *ep, c_expr_t *out);
static int ep_parse_bitxor(ep_t *ep, c_expr_t *out);
static int ep_parse_bitor(ep_t *ep, c_expr_t *out);
static int ep_parse_and(ep_t *ep, c_expr_t *out);

static int ep_parse_postfix(ep_t *ep, eval_result_t *res, int stop_at_binop)
{
    for (;;) {
        ep->cur = skip_spaces(ep->cur);

        if (stop_at_binop && ep_is_binop_at(ep->cur))
            break;

        if (*ep->cur == '.') {
            char member[64];

            ep->cur = parse_c_ident(ep->cur + 1, member, sizeof(member));

            if (!ep->cur || !member[0]) {
                printf("expected member name after '.'\n");
                return -1;
            }

            if (apply_member(res, member) != 0)
                return -1;
        } else if (*ep->cur == '-' && ep->cur[1] == '>') {
            char base_label[256];
            char member[64];

            strncpy(base_label, res->label, sizeof(base_label) - 1);
            base_label[sizeof(base_label) - 1] = '\0';

            if (apply_deref(res, 0) != 0)
                return -1;

            ep->cur += 2;
            ep->cur = skip_spaces(ep->cur);
            ep->cur = parse_c_ident(ep->cur, member, sizeof(member));

            if (!ep->cur || !member[0]) {
                printf("expected member name after '->'\n");
                return -1;
            }

            if (resolve_member(res, member) != 0)
                return -1;

            strncpy(res->label, base_label, sizeof(res->label) - 1);
            res->label[sizeof(res->label) - 1] = '\0';
            append_label(res->label, sizeof(res->label), "->");
            append_label(res->label, sizeof(res->label), member);
        } else if (*ep->cur == '[') {
            c_expr_t idx;

            ep->cur = skip_spaces(ep->cur + 1);

            if (ep_parse_or(ep, &idx) != 0)
                return -1;

            ep->cur = skip_spaces(ep->cur);

            if (*ep->cur != ']') {
                printf("expected ']'\n");
                return -1;
            }

            ep->cur++;

            if (apply_index(res, idx.value) != 0)
                return -1;
        } else {
            break;
        }
    }

    return 0;
}

static int ep_require_scalar(c_expr_t *n)
{
    if (n->has_lval && ep_is_aggregate_lval(&n->lval)) {
        printf("aggregate value in expression: %s\n", n->lval.label);
        return -1;
    }

    if (n->has_lval && ep_load_scalar(n) != 0)
        return -1;

    n->has_lval = 0;
    return 0;
}

static int ep_parse_primary(ep_t *ep, c_expr_t *out)
{
    int reg = ep_parse_register(ep, out);

    if (reg != 0)
        return reg > 0 ? 0 : -1;

    ep->cur = skip_spaces(ep->cur);

    if (*ep->cur == '(') {
        ep->cur++;
        if (ep_parse_or(ep, out) != 0)
            return -1;

        ep->cur = skip_spaces(ep->cur);

        if (*ep->cur != ')') {
            printf("expected ')'\n");
            return -1;
        }

        ep->cur++;
        return 0;
    }

    if ((*ep->cur >= '0' && *ep->cur <= '9') ||
        ((*ep->cur == '0' || *ep->cur == '-') &&
         ep->cur[1] == 'x') ||
        (*ep->cur == '0' && ep->cur[1] >= '0' && ep->cur[1] <= '7')) {
        char *end;
        unsigned long uval = strtoul(ep->cur, &end, 0);

        if (end == ep->cur) {
            printf("invalid number\n");
            return -1;
        }

        ep->cur = end;
        out->value = (long)uval;
        out->has_lval = 0;
        return 0;
    }

    if (!ep_is_ident_start(*ep->cur)) {
        printf("syntax error near '%s'\n", ep->cur);
        return -1;
    }

    char name[64];

    ep->cur = parse_c_ident(ep->cur, name, sizeof(name));

    if (!name[0]) {
        printf("expected identifier\n");
        return -1;
    }

    eval_result_t res;

    if (read_var_addr(name, ep->rip, &res.addr, &res.type_off) != 0) {
        printf("unknown variable: %s\n", name);
        return -1;
    }

    strncpy(res.label, name, sizeof(res.label) - 1);
    res.label[sizeof(res.label) - 1] = '\0';

    if (ep_parse_postfix(ep, &res, 0) != 0)
        return -1;

    out->has_lval = 1;
    out->lval = res;
    return ep_load_scalar(out);
}

static int ep_parse_unary(ep_t *ep, c_expr_t *out)
{
    ep->cur = skip_spaces(ep->cur);

    if (*ep->cur == '+') {
        ep->cur++;
        if (ep_parse_unary(ep, out) != 0)
            return -1;
        return ep_require_scalar(out);
    }

    if (*ep->cur == '-') {
        ep->cur++;
        if (ep_parse_unary(ep, out) != 0)
            return -1;
        if (ep_require_scalar(out) != 0)
            return -1;
        out->value = -out->value;
        return 0;
    }

    if (*ep->cur == '~') {
        ep->cur++;
        if (ep_parse_unary(ep, out) != 0)
            return -1;
        if (ep_require_scalar(out) != 0)
            return -1;
        out->value = ~out->value;
        return 0;
    }

    if (*ep->cur == '!') {
        ep->cur++;
        if (ep_parse_unary(ep, out) != 0)
            return -1;
        if (ep_require_scalar(out) != 0)
            return -1;
        out->value = !out->value;
        return 0;
    }

    if (*ep->cur == '*') {
        ep->cur++;
        if (ep_parse_unary(ep, out) != 0)
            return -1;

        if (!out->has_lval) {
            printf("invalid dereference\n");
            return -1;
        }

        if (apply_deref(&out->lval, 1) != 0)
            return -1;

        return ep_load_scalar(out);
    }

    return ep_parse_primary(ep, out);
}

static int ep_parse_mul(ep_t *ep, c_expr_t *out)
{
    if (ep_parse_unary(ep, out) != 0)
        return -1;

    for (;;) {
        ep->cur = skip_spaces(ep->cur);

        char op = *ep->cur;

        if (op != '*' && op != '/' && op != '%')
            break;

        ep->cur++;

        c_expr_t rhs;

        if (ep_parse_unary(ep, &rhs) != 0)
            return -1;

        if (ep_require_scalar(out) != 0 || ep_require_scalar(&rhs) != 0)
            return -1;

        if (op == '*')
            out->value *= rhs.value;
        else if (op == '/') {
            if (rhs.value == 0) {
                printf("division by zero\n");
                return -1;
            }
            out->value /= rhs.value;
        } else {
            if (rhs.value == 0) {
                printf("division by zero\n");
                return -1;
            }
            out->value %= rhs.value;
        }
    }

    return 0;
}

static int ep_parse_add(ep_t *ep, c_expr_t *out)
{
    if (ep_parse_mul(ep, out) != 0)
        return -1;

    for (;;) {
        ep->cur = skip_spaces(ep->cur);

        char op = *ep->cur;

        if (op != '+' && op != '-')
            break;

        ep->cur++;

        c_expr_t rhs;

        if (ep_parse_mul(ep, &rhs) != 0)
            return -1;

        if (ep_require_scalar(out) != 0 || ep_require_scalar(&rhs) != 0)
            return -1;

        if (op == '+')
            out->value += rhs.value;
        else
            out->value -= rhs.value;
    }

    return 0;
}

static int ep_parse_shift(ep_t *ep, c_expr_t *out)
{
    if (ep_parse_add(ep, out) != 0)
        return -1;

    for (;;) {
        ep->cur = skip_spaces(ep->cur);

        int is_left;

        if (!strncmp(ep->cur, "<<", 2)) {
            ep->cur += 2;
            is_left = 1;
        } else if (!strncmp(ep->cur, ">>", 2)) {
            ep->cur += 2;
            is_left = 0;
        } else {
            break;
        }

        c_expr_t rhs;

        if (ep_parse_add(ep, &rhs) != 0)
            return -1;

        if (ep_require_scalar(out) != 0 || ep_require_scalar(&rhs) != 0)
            return -1;

        if (is_left)
            out->value = (long)((unsigned long)out->value <<
                                (unsigned)(rhs.value & 63));
        else
            out->value = (long)((unsigned long)out->value >>
                                (unsigned)(rhs.value & 63));
    }

    return 0;
}

static int ep_parse_rel(ep_t *ep, c_expr_t *out)
{
    if (ep_parse_shift(ep, out) != 0)
        return -1;

    for (;;) {
        ep->cur = skip_spaces(ep->cur);

        int op = 0;

        if (!strncmp(ep->cur, "<=", 2)) {
            op = 1;
            ep->cur += 2;
        } else if (!strncmp(ep->cur, ">=", 2)) {
            op = 2;
            ep->cur += 2;
        } else if (*ep->cur == '<') {
            op = 3;
            ep->cur++;
        } else if (*ep->cur == '>') {
            op = 4;
            ep->cur++;
        } else {
            break;
        }

        c_expr_t rhs;

        if (ep_parse_shift(ep, &rhs) != 0)
            return -1;

        if (ep_require_scalar(out) != 0 || ep_require_scalar(&rhs) != 0)
            return -1;

        switch (op) {
        case 1:
            out->value = out->value <= rhs.value;
            break;
        case 2:
            out->value = out->value >= rhs.value;
            break;
        case 3:
            out->value = out->value < rhs.value;
            break;
        case 4:
            out->value = out->value > rhs.value;
            break;
        }

        out->value = out->value ? 1 : 0;
    }

    return 0;
}

static int ep_parse_eq(ep_t *ep, c_expr_t *out)
{
    if (ep_parse_rel(ep, out) != 0)
        return -1;

    for (;;) {
        ep->cur = skip_spaces(ep->cur);

        int op = 0;

        if (!strncmp(ep->cur, "==", 2)) {
            op = 1;
            ep->cur += 2;
        } else if (!strncmp(ep->cur, "!=", 2)) {
            op = 2;
            ep->cur += 2;
        } else {
            break;
        }

        c_expr_t rhs;

        if (ep_parse_rel(ep, &rhs) != 0)
            return -1;

        if (ep_require_scalar(out) != 0 || ep_require_scalar(&rhs) != 0)
            return -1;

        if (op == 1)
            out->value = out->value == rhs.value;
        else
            out->value = out->value != rhs.value;

        out->value = out->value ? 1 : 0;
    }

    return 0;
}

static int ep_parse_bitand(ep_t *ep, c_expr_t *out)
{
    if (ep_parse_eq(ep, out) != 0)
        return -1;

    while (*skip_spaces(ep->cur) == '&' && ep->cur[1] != '&') {
        ep->cur = skip_spaces(ep->cur) + 1;

        c_expr_t rhs;

        if (ep_parse_eq(ep, &rhs) != 0)
            return -1;

        if (ep_require_scalar(out) != 0 || ep_require_scalar(&rhs) != 0)
            return -1;

        out->value = (long)((unsigned long)out->value &
                            (unsigned long)rhs.value);
    }

    return 0;
}

static int ep_parse_bitxor(ep_t *ep, c_expr_t *out)
{
    if (ep_parse_bitand(ep, out) != 0)
        return -1;

    while (*skip_spaces(ep->cur) == '^') {
        ep->cur = skip_spaces(ep->cur) + 1;

        c_expr_t rhs;

        if (ep_parse_bitand(ep, &rhs) != 0)
            return -1;

        if (ep_require_scalar(out) != 0 || ep_require_scalar(&rhs) != 0)
            return -1;

        out->value = (long)((unsigned long)out->value ^
                            (unsigned long)rhs.value);
    }

    return 0;
}

static int ep_parse_bitor(ep_t *ep, c_expr_t *out)
{
    if (ep_parse_bitxor(ep, out) != 0)
        return -1;

    while (*skip_spaces(ep->cur) == '|' && ep->cur[1] != '|') {
        ep->cur = skip_spaces(ep->cur) + 1;

        c_expr_t rhs;

        if (ep_parse_bitxor(ep, &rhs) != 0)
            return -1;

        if (ep_require_scalar(out) != 0 || ep_require_scalar(&rhs) != 0)
            return -1;

        out->value = (long)((unsigned long)out->value |
                            (unsigned long)rhs.value);
    }

    return 0;
}

static int ep_parse_and(ep_t *ep, c_expr_t *out)
{
    if (ep_parse_bitor(ep, out) != 0)
        return -1;

    while (!strncmp(skip_spaces(ep->cur), "&&", 2)) {
        ep->cur = skip_spaces(ep->cur) + 2;

        c_expr_t rhs;

        if (ep_parse_bitor(ep, &rhs) != 0)
            return -1;

        if (ep_require_scalar(out) != 0 || ep_require_scalar(&rhs) != 0)
            return -1;

        out->value = out->value && rhs.value ? 1 : 0;
    }

    return 0;
}

static int ep_parse_or(ep_t *ep, c_expr_t *out)
{
    if (ep_parse_and(ep, out) != 0)
        return -1;

    while (!strncmp(skip_spaces(ep->cur), "||", 2)) {
        ep->cur = skip_spaces(ep->cur) + 2;

        c_expr_t rhs;

        if (ep_parse_and(ep, &rhs) != 0)
            return -1;

        if (ep_require_scalar(out) != 0 || ep_require_scalar(&rhs) != 0)
            return -1;

        out->value = out->value || rhs.value ? 1 : 0;
    }

    ep->cur = skip_spaces(ep->cur);
    return 0;
}

static int ep_parse_expr(ep_t *ep, c_expr_t *out)
{
    if (ep_parse_or(ep, out) != 0)
        return -1;

    if (*ep->cur != '\0') {
        printf("syntax error near '%s'\n", ep->cur);
        return -1;
    }

    return 0;
}

static void print_c_expr(c_expr_t *node, const char *label, print_format_t fmt)
{
    if (fmt == PRINT_FMT_STRING) {
        unsigned long str_addr;

        if (node->has_lval)
            str_addr = resolve_string_addr(node->lval.addr,
                                           node->lval.type_off);
        else
            str_addr = (unsigned long)node->value;

        print_string_value(label, str_addr);
        return;
    }

    if (node->has_lval && ep_is_aggregate_lval(&node->lval)) {
        print_eval_result(&node->lval, fmt);
        return;
    }

    print_value(label, (unsigned long)node->value, fmt);
}

static int eval_lvalue(const char *expr,
                       unsigned long rip,
                       eval_result_t *res)
{
    ep_t ep = { .cur = expr, .rip = rip };
    const char *p = skip_spaces(ep.cur);
    int deref = 0;

    while (*p == '*') {
        deref = 1;
        p = skip_spaces(p + 1);
    }

    char name[64];

    p = parse_c_ident(p, name, sizeof(name));

    if (!p || !name[0])
        return -1;

    if (read_var_addr(name, rip, &res->addr, &res->type_off) != 0) {
        printf("unknown variable: %s\n", name);
        return -1;
    }

    strncpy(res->label, name, sizeof(res->label) - 1);
    res->label[sizeof(res->label) - 1] = '\0';

    ep.cur = p;

    if (deref && apply_deref(res, 1) != 0)
        return -1;

    if (ep_parse_postfix(&ep, res, 1) != 0)
        return -1;

    ep.cur = skip_spaces(ep.cur);

    if (*ep.cur != '\0') {
        printf("not an lvalue: %s\n", expr);
        return -1;
    }

    return 0;
}

static int eval_expression(const char *expr,
                           unsigned long rip,
                           c_expr_t *out)
{
    ep_t ep = { .cur = expr, .rip = rip };

    return ep_parse_expr(&ep, out);
}

static int set_variable_value(const char *args, unsigned long rip)
{
    char buf[256];
    char *eq;

    strncpy(buf, args, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    const char *lhs = buf;

    if (!strncmp(lhs, "variable ", 9))
        lhs += 9;

    lhs = skip_spaces(lhs);
    eq = strchr((char *)lhs, '=');

    if (!eq)
        return 0;

    if (eq == lhs) {
        printf("missing variable name\n");
        return 1;
    }

    *eq = '\0';
    trim_line((char *)lhs);

    const char *rhs = skip_spaces(eq + 1);

    if (!*rhs) {
        printf("missing value\n");
        return 1;
    }

    eval_result_t res;

    if (eval_lvalue(lhs, rip, &res) != 0)
        return 1;

    ep_t ep = { .cur = rhs, .rip = rip };
    c_expr_t val;

    if (ep_parse_expr(&ep, &val) != 0)
        return 1;

    type_info_t ti = {
        .kind = TYPE_BASE,
        .size = 4,
        .encoding = DW_ATE_signed,
    };

    if (res.type_off != 0 &&
        get_cached_type(res.type_off, &ti) != 0) {
        printf("unknown type for %s\n", res.label);
        return 1;
    }

    if (write_typed_value(res.addr, &ti, (unsigned long)val.value) != 0)
        return 1;

    print_eval_result(&res, PRINT_FMT_DEFAULT);
    return 1;
}

static int set_register_value(const char *args, unsigned long rip)
{
    char buf[256];
    char *eq;
    const reg_info_t *reg;

    strncpy(buf, args, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    const char *lhs = skip_spaces(buf);
    int forced = (*lhs == '$');

    eq = strchr((char *)lhs, '=');

    if (!eq)
        return 0;

    if (eq == lhs) {
        printf("missing register name\n");
        return 1;
    }

    *eq = '\0';
    trim_line((char *)lhs);

    if (lookup_register(lhs, &reg) != 0) {
        if (forced) {
            printf("unknown register: %s\n", lhs);
            return 1;
        }
        return 0;
    }

    const char *rhs = skip_spaces(eq + 1);

    if (!*rhs) {
        printf("missing value\n");
        return 1;
    }

    ep_t ep = { .cur = rhs, .rip = rip };
    c_expr_t val;

    if (ep_parse_expr(&ep, &val) != 0)
        return 1;

    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs) == -1) {
        perror("ptrace getregs");
        return 1;
    }

    *(unsigned long long *)((char *)&regs + reg->offset) =
        (unsigned long long)val.value;

    if (ptrace(PTRACE_SETREGS, dbg.pid, 0, &regs) == -1) {
        perror("ptrace setregs");
        return 1;
    }

    printf("$%s = 0x%llx\n", reg->name,
           (unsigned long long)val.value);
    return 1;
}

static int parse_print_format(const char **expr, print_format_t *fmt)
{
    const char *p = *expr;

    while (*p == ' ')
        p++;

    if (*p != '/')
        return 0;

    p++;

    if (!*p)
        return -1;

    switch (*p++) {
    case 'd':
    case 'i':
        *fmt = PRINT_FMT_DECIMAL;
        break;
    case 'x':
        *fmt = PRINT_FMT_HEX;
        break;
    case 'o':
        *fmt = PRINT_FMT_OCTAL;
        break;
    case 't':
        *fmt = PRINT_FMT_BINARY;
        break;
    case 'u':
        *fmt = PRINT_FMT_UNSIGNED;
        break;
    case 'c':
        *fmt = PRINT_FMT_CHAR;
        break;
    case 's':
        *fmt = PRINT_FMT_STRING;
        break;
    case 'a':
        *fmt = PRINT_FMT_POINTER;
        break;
    default:
        return -1;
    }

    while (*p == ' ')
        p++;

    *expr = p;
    return 1;
}

void set_command(const char *args)
{
    char buf[256];

    strncpy(buf, args, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    trim_line(buf);
    args = buf;

    while (*args == ' ' || *args == '\t')
        args++;

    if (!strncmp(args, "language ", 9)) {
        args += 9;

        while (*args == ' ')
            args++;

        if (!strcmp(args, "c")) {
            print_settings.language = LANG_C;
            printf("Language set to C.\n");
        } else {
            printf("unknown language (only 'c' is supported)\n");
        }
        return;
    }

    if (!strncmp(args, "output-radix ", 13)) {
        args += 13;

        while (*args == ' ')
            args++;

        char name[32];

        if (sscanf(args, "%31s", name) != 1) {
            printf("usage: set output-radix {8|10|16|2}\n");
            return;
        }

        print_format_t fmt = PRINT_FMT_DEFAULT;

        if (!strcmp(name, "8"))
            fmt = PRINT_FMT_OCTAL;
        else if (!strcmp(name, "10"))
            fmt = PRINT_FMT_DECIMAL;
        else if (!strcmp(name, "16"))
            fmt = PRINT_FMT_HEX;
        else if (!strcmp(name, "2"))
            fmt = PRINT_FMT_BINARY;
        else {
            printf("unknown output radix: %s\n", name);
            return;
        }

        print_settings.format = fmt;
        printf("Output radix set to %s.\n", name);
        return;
    }

    if (!strncmp(args, "print format ", 13)) {
        args += 13;

        while (*args == ' ')
            args++;

        char name[32];

        if (sscanf(args, "%31s", name) != 1) {
            printf("usage: set print format "
                   "{decimal|hex|octal|binary|unsigned|char|pointer}\n");
            return;
        }

        print_format_t fmt = parse_format_name(name);

        if (fmt == PRINT_FMT_DEFAULT) {
            printf("unknown print format: %s\n", name);
            return;
        }

        print_settings.format = fmt;
        printf("Print format set to %s.\n", format_name(fmt));
        return;
    }

    if (!strncmp(args, "print array ", 12)) {
        args += 12;

        while (*args == ' ')
            args++;

        char name[32];

        if (sscanf(args, "%31s", name) != 1) {
            printf("usage: set print array {on|off}\n");
            return;
        }

        int value;

        if (parse_on_off(name, &value) != 0) {
            printf("usage: set print array {on|off}\n");
            return;
        }

        print_settings.print_array = value;
        printf("Print array set to %s.\n", value ? "on" : "off");
        return;
    }

    if (!strncmp(args, "print pretty ", 13)) {
        args += 13;

        while (*args == ' ')
            args++;

        char name[32];

        if (sscanf(args, "%31s", name) != 1) {
            printf("usage: set print pretty {on|off}\n");
            return;
        }

        int value;

        if (parse_on_off(name, &value) != 0) {
            printf("usage: set print pretty {on|off}\n");
            return;
        }

        print_settings.print_pretty = value;
        printf("Print pretty set to %s.\n", value ? "on" : "off");
        return;
    }

    if (!strncmp(args, "print elements ", 15)) {
        args += 15;

        while (*args == ' ')
            args++;

        char name[32];

        if (sscanf(args, "%31s", name) != 1) {
            printf("usage: set print elements {unlimited|<count>}\n");
            return;
        }

        if (!strcmp(name, "unlimited") || !strcmp(name, "0")) {
            print_settings.print_elements = -1;
            printf("Print elements set to unlimited.\n");
            return;
        }

        char *end;
        long count = strtol(name, &end, 10);

        if (*end != '\0' || count < 0) {
            printf("usage: set print elements {unlimited|<count>}\n");
            return;
        }

        print_settings.print_elements = (int)count;
        printf("Print elements set to %ld.\n", count);
        return;
    }

    if (strchr(args, '=')) {
        if (!dbg.running) {
            printf("no process\n");
            return;
        }

        struct user_regs_struct regs;

        ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs);

        if (set_register_value(args, regs.rip))
            return;

        if (set_variable_value(args, regs.rip))
            return;
    }

    printf("usage:\n");
    printf("  set $<register> = <expr>\n");
    printf("  set variable <expr> = <value>\n");
    printf("  set <expr> = <value>\n");
    printf("  set language c\n");
    printf("  set output-radix {8|10|16|2}\n");
    printf("  set print format "
           "{decimal|hex|octal|binary|unsigned|char|pointer}\n");
    printf("  set print array {on|off}\n");
    printf("  set print pretty {on|off}\n");
    printf("  set print elements {unlimited|<count>}\n");
}

void show_command(const char *args)
{
    char buf[256];

    strncpy(buf, args, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    trim_line(buf);
    args = buf;

    while (*args == ' ' || *args == '\t')
        args++;

    if (!strcmp(args, "language") || !strcmp(args, "")) {
        if (*args == '\0')
            show_print_settings();
        else
            printf("Language: C\n");
        return;
    }

    if (!strcmp(args, "print")) {
        show_print_settings();
        return;
    }

    printf("usage:\n");
    printf("  show language\n");
    printf("  show print\n");
}

void print_expression(const char *expr)
{
    if (!dbg.running) {
        printf("no process\n");
        return;
    }

    if (print_settings.language != LANG_C) {
        printf("only C language is supported\n");
        return;
    }

    while (*expr == ' ' || *expr == '\t')
        expr++;

    char buf[256];
    strncpy(buf, expr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    size_t len = strlen(buf);

    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    const char *p = buf;
    print_format_t fmt = PRINT_FMT_DEFAULT;
    int pf = parse_print_format(&p, &fmt);

    if (pf < 0) {
        printf("unknown print format\n");
        return;
    }

    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs);

    c_expr_t node;

    if (eval_expression(p, regs.rip, &node) != 0) {
        if (!*skip_spaces(p))
            printf("usage: print [/format] expr\n");
        return;
    }

    print_c_expr(&node, p, fmt);
}
