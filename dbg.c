#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <elf.h>

typedef struct {
    pid_t pid;
    int running;
    int is_pie;
    unsigned long load_base;
} debugger_t;

debugger_t dbg = {0};
char debuggee_path[512];
char debuggee_realpath[512];

#define MAX_BREAKPOINTS 32

typedef struct {
    unsigned long addr;
    long original_data;
    int enabled;
} breakpoint_t;

breakpoint_t breakpoints[MAX_BREAKPOINTS];

int bp_count = 0;

typedef struct {
    int active;
    int uses_existing;
    unsigned long addr;
    long original_data;
} finish_bp_t;

finish_bp_t finish_bp = {0};
finish_bp_t next_bp = {0};

#define MAX_SYMBOLS 1024

typedef struct {
    char name[256];
    unsigned long addr;
    unsigned long size;
    unsigned char type;
} symbol_t;

symbol_t symbols[MAX_SYMBOLS];
int sym_count = 0;

#define MAX_LINE_ENTRIES 4096

typedef struct {
    unsigned long addr;
    char file[512];
    int line;
} line_entry_t;

line_entry_t line_entries[MAX_LINE_ENTRIES];
int line_entry_count = 0;
unsigned long line_addr_min = 0;
unsigned long line_addr_max = 0;

#define MAX_VARS 256

typedef enum {
    VAR_FBREG,
    VAR_ADDR
} var_loc_t;

typedef struct {
    char name[64];
    unsigned long scope_low;
    unsigned long scope_high;
    var_loc_t loc;
    long fbreg;
    unsigned long addr;
    uint32_t type_off;
} var_entry_t;

var_entry_t vars[MAX_VARS];
int var_count = 0;

#define DW_TAG_array_type       0x01
#define DW_TAG_member           0x0d
#define DW_TAG_pointer_type     0x0f
#define DW_TAG_structure_type   0x13
#define DW_TAG_typedef          0x16
#define DW_TAG_subrange_type    0x21
#define DW_TAG_base_type        0x24
#define DW_TAG_const_type       0x26

#define DW_AT_type              0x49
#define DW_AT_byte_size         0x0b
#define DW_AT_encoding          0x3e
#define DW_AT_data_member_location 0x38
#define DW_AT_upper_bound       0x2f

#define DW_ATE_signed           0x05
#define DW_ATE_unsigned         0x07

typedef enum {
    TYPE_UNKNOWN,
    TYPE_BASE,
    TYPE_POINTER,
    TYPE_STRUCT,
    TYPE_ARRAY,
    TYPE_ALIAS,
} type_kind_t;

typedef struct {
    char name[64];
    uint32_t type_off;
    long offset;
} dwarf_member_t;

typedef struct {
    type_kind_t kind;
    size_t size;
    int encoding;
    uint32_t ref_off;
    char struct_name[64];
    dwarf_member_t members[16];
    int member_count;
    uint32_t elem_type_off;
    int array_count;
} type_info_t;

#define MAX_TYPE_CACHE 128

typedef struct {
    uint32_t off;
    type_info_t info;
} type_cache_entry_t;

static type_cache_entry_t type_cache[MAX_TYPE_CACHE];
static int type_cache_count = 0;
static size_t current_cu_base = 0;

static int get_type_info(uint32_t off, type_info_t *out);

#define DW_TAG_compile_unit     0x11
#define DW_TAG_subprogram       0x2e
#define DW_TAG_lexical_block    0x0b
#define DW_TAG_variable         0x34
#define DW_TAG_formal_parameter 0x05

#define DW_AT_sibling           0x01
#define DW_AT_location          0x02
#define DW_AT_name              0x03
#define DW_AT_low_pc            0x11
#define DW_AT_high_pc           0x12

#define DWARF_FORM_addr            0x01
#define DWARF_FORM_string          0x08
#define DWARF_FORM_data1           0x0b
#define DWARF_FORM_data2           0x05
#define DWARF_FORM_data4           0x06
#define DWARF_FORM_data8           0x07
#define DWARF_FORM_strp            0x0e
#define DWARF_FORM_ref4            0x13
#define DWARF_FORM_flag_present    0x19
#define DWARF_FORM_line_strp       0x1f
#define DWARF_FORM_exprloc         0x1e
#define DWARF_FORM_implicit_const  0x21
#define DWARF_FORM_sec_offset      0x17
#define DWARF_FORM_block1          0x18

#define DW_OP_addr              0x03
#define DW_OP_fbreg             0x91

#define MAX_ABBREVS 64

static uint64_t read_uleb128(const uint8_t *data, size_t len, size_t *off);
static int64_t read_sleb128(const uint8_t *data, size_t len, size_t *off);
long read_memory(unsigned long addr);
static int peek_word(unsigned long addr, unsigned long *value);
static int poke_word(unsigned long addr, unsigned long value);
int lookup_symbol(const char *name, unsigned long *addr);
static unsigned long to_debug_addr(unsigned long addr);
static unsigned long to_runtime_addr(unsigned long addr);

typedef struct {
    uint64_t code;
    uint64_t tag;
    int has_children;
    uint8_t attr[32];
    uint8_t form[32];
    int64_t implicit[32];
    int nattr;
} dwarf_abbrev_t;

static dwarf_abbrev_t abbrevs[MAX_ABBREVS];
static int abbrev_count = 0;
static const uint8_t *debug_info;
static size_t debug_info_size;
static const uint8_t *debug_str;
static size_t debug_str_size;
static int dwarf_addr_size = 8;

static dwarf_abbrev_t *find_abbrev(uint64_t code)
{
    for (int i = 0; i < abbrev_count; i++) {
        if (abbrevs[i].code == code)
            return &abbrevs[i];
    }

    return NULL;
}

static void load_abbrev_table(const uint8_t *data, size_t len)
{
    abbrev_count = 0;
    size_t off = 0;

    while (off < len && abbrev_count < MAX_ABBREVS) {
        uint64_t code = read_uleb128(data, len, &off);

        if (code == 0)
            break;

        dwarf_abbrev_t *ab = &abbrevs[abbrev_count++];

        ab->code = code;
        ab->tag = read_uleb128(data, len, &off);
        ab->has_children = data[off++];
        ab->nattr = 0;

        while (off < len) {
            uint64_t attr = read_uleb128(data, len, &off);
            uint64_t form = read_uleb128(data, len, &off);

            if (attr == 0 && form == 0)
                break;

            int i = ab->nattr;

            ab->attr[i] = attr;
            ab->form[i] = form;

            if (form == DWARF_FORM_implicit_const)
                ab->implicit[i] = read_sleb128(data, len, &off);
            else
                ab->implicit[i] = 0;

            ab->nattr++;
        }
    }
}

static void skip_attr(uint8_t form, int64_t implicit,
                      const uint8_t *data, size_t len, size_t *off)
{
    if (form == DWARF_FORM_implicit_const || form == DWARF_FORM_flag_present)
        return;

    switch (form) {
    case DWARF_FORM_string:
        while (*off < len && data[(*off)++])
            ;
        break;
    case DWARF_FORM_strp:
    case DWARF_FORM_ref4:
    case DWARF_FORM_sec_offset:
    case DWARF_FORM_line_strp:
        *off += 4;
        break;
    case DWARF_FORM_addr:
        *off += dwarf_addr_size;
        break;
    case DWARF_FORM_data1:
        (*off)++;
        break;
    case DWARF_FORM_data2:
        *off += 2;
        break;
    case DWARF_FORM_data4:
        *off += 4;
        break;
    case DWARF_FORM_data8:
        *off += 8;
        break;
    case DWARF_FORM_block1: {
        if (*off >= len)
            break;
        *off += 1 + data[*off];
        break;
    }
    case DWARF_FORM_exprloc: {
        uint64_t blen = read_uleb128(data, len, off);
        *off += blen;
        break;
    }
    default:
        break;
    }
}

static const char *read_attr_string(uint8_t form, int64_t implicit,
                                    const uint8_t *data, size_t len,
                                    size_t *off)
{
    if (form == DWARF_FORM_string)
        return (const char *)(data + *off);

    if (form == DWARF_FORM_strp) {
        uint32_t str_off = *(uint32_t *)(data + *off);
        return (const char *)(debug_str + str_off);
    }

    (void)implicit;
    return NULL;
}

static void add_var_entry(const char *name,
                          unsigned long scope_low,
                          unsigned long scope_high,
                          const uint8_t *loc,
                          size_t loc_len,
                          uint32_t type_off)
{
    if (!name || !name[0] || var_count >= MAX_VARS)
        return;

    var_entry_t *v = &vars[var_count];

    if (loc_len >= 2 && loc[0] == DW_OP_fbreg) {
        size_t o = 1;
        v->loc = VAR_FBREG;
        v->fbreg = read_sleb128(loc, loc_len, &o);
    } else if (loc_len >= 1 + (size_t)dwarf_addr_size &&
               loc[0] == DW_OP_addr) {
        v->loc = VAR_ADDR;
        v->addr = 0;
        for (int i = 0; i < dwarf_addr_size; i++)
            v->addr |= (unsigned long)loc[1 + i] << (8 * i);
    } else {
        return;
    }

    strncpy(v->name, name, sizeof(v->name) - 1);
    v->name[sizeof(v->name) - 1] = '\0';
    v->scope_low = scope_low;
    v->scope_high = scope_high;
    v->type_off = type_off;
    var_count++;
}

static uint64_t read_attr_number(uint8_t form, const uint8_t *data)
{
    switch (form) {
    case DWARF_FORM_data1:
        return data[0];
    case DWARF_FORM_data2:
        return *(uint16_t *)data;
    case DWARF_FORM_data4:
        return *(uint32_t *)data;
    case DWARF_FORM_data8:
        return *(uint64_t *)data;
    default:
        return 0;
    }
}

static int type_cache_lookup(uint32_t off, type_info_t *out)
{
    for (int i = 0; i < type_cache_count; i++) {
        if (type_cache[i].off == off) {
            *out = type_cache[i].info;
            return 0;
        }
    }

    return -1;
}

static int get_cached_type(uint32_t off, type_info_t *out)
{
    if (off == 0)
        return -1;

    if (type_cache_lookup(off, out) == 0)
        return 0;

    return get_type_info(off, out);
}

static void cache_type(uint32_t off, const type_info_t *info)
{
    for (int i = 0; i < type_cache_count; i++) {
        if (type_cache[i].off == off)
            return;
    }

    if (type_cache_count >= MAX_TYPE_CACHE)
        return;

    type_cache[type_cache_count].off = off;
    type_cache[type_cache_count].info = *info;
    type_cache_count++;
}

static void parse_struct_members(size_t *off,
                                 size_t unit_end,
                                 type_info_t *ti)
{
    while (*off < unit_end) {
        size_t die_start = *off;
        uint64_t abcode = read_uleb128(debug_info, unit_end, off);

        if (abcode == 0)
            return;

        dwarf_abbrev_t *ab = find_abbrev(abcode);

        if (!ab)
            return;

        char member_name[64] = {0};
        uint32_t member_type = 0;
        long member_offset = 0;
        int has_offset = 0;

        for (int i = 0; i < ab->nattr; i++) {
            size_t attr_off = *off;

            if (ab->attr[i] == DW_AT_name) {
                const char *s = read_attr_string(ab->form[i], ab->implicit[i],
                                                 debug_info, debug_info_size,
                                                 &attr_off);
                if (s)
                    strncpy(member_name, s, sizeof(member_name) - 1);
            } else if (ab->attr[i] == DW_AT_type &&
                       ab->form[i] == DWARF_FORM_ref4) {
                uint32_t ref = *(uint32_t *)(debug_info + attr_off);
                member_type = (uint32_t)(current_cu_base + ref);
            } else if (ab->attr[i] == DW_AT_data_member_location) {
                if (ab->form[i] == DWARF_FORM_data1 ||
                    ab->form[i] == DWARF_FORM_data2 ||
                    ab->form[i] == DWARF_FORM_data4 ||
                    ab->form[i] == DWARF_FORM_data8) {
                    member_offset =
                        (long)read_attr_number(ab->form[i],
                                               debug_info + attr_off);
                    has_offset = 1;
                }
            }

            skip_attr(ab->form[i], ab->implicit[i],
                      debug_info, unit_end, off);
        }

        if (ab->tag == DW_TAG_member && member_name[0] && member_type &&
            ti->member_count < (int)(sizeof(ti->members) /
                                     sizeof(ti->members[0]))) {
            dwarf_member_t *m = &ti->members[ti->member_count++];

            strncpy(m->name, member_name, sizeof(m->name) - 1);
            m->type_off = member_type;
            m->offset = has_offset ? member_offset : 0;
        }

        if (ab->has_children)
            parse_struct_members(off, unit_end, ti);

        (void)die_start;
    }
}

static int parse_type_die(uint32_t off, type_info_t *out)
{
    if (off == 0 || off >= debug_info_size)
        return -1;

    type_info_t cached;

    if (type_cache_lookup(off, &cached) == 0) {
        *out = cached;
        return 0;
    }

    size_t die_off = off;
    uint64_t abcode = read_uleb128(debug_info, debug_info_size, &die_off);

    if (abcode == 0)
        return -1;

    dwarf_abbrev_t *ab = find_abbrev(abcode);

    if (!ab)
        return -1;

    type_info_t ti = {0};

    ti.kind = TYPE_UNKNOWN;
    ti.size = 0;
    ti.ref_off = 0;
    ti.array_count = 0;

    uint32_t ref_type = 0;
    int array_upper = -1;

    for (int i = 0; i < ab->nattr; i++) {
        size_t attr_off = die_off;

        if (ab->attr[i] == DW_AT_name) {
            const char *s = read_attr_string(ab->form[i], ab->implicit[i],
                                             debug_info, debug_info_size,
                                             &attr_off);
            if (s && ab->tag == DW_TAG_structure_type)
                strncpy(ti.struct_name, s, sizeof(ti.struct_name) - 1);
        } else if (ab->attr[i] == DW_AT_byte_size &&
                   (ab->form[i] == DWARF_FORM_data1 ||
                    ab->form[i] == DWARF_FORM_data2 ||
                    ab->form[i] == DWARF_FORM_data4 ||
                    ab->form[i] == DWARF_FORM_data8)) {
            ti.size = (size_t)read_attr_number(ab->form[i],
                                               debug_info + attr_off);
        } else if (ab->attr[i] == DW_AT_encoding &&
                   (ab->form[i] == DWARF_FORM_data1 ||
                    ab->form[i] == DWARF_FORM_data2 ||
                    ab->form[i] == DWARF_FORM_data4)) {
            ti.encoding = (int)read_attr_number(ab->form[i],
                                                debug_info + attr_off);
        } else if (ab->attr[i] == DW_AT_type &&
                   ab->form[i] == DWARF_FORM_ref4) {
            uint32_t ref = *(uint32_t *)(debug_info + attr_off);
            ref_type = (uint32_t)(current_cu_base + ref);
        } else if (ab->attr[i] == DW_AT_upper_bound &&
                   (ab->form[i] == DWARF_FORM_data1 ||
                    ab->form[i] == DWARF_FORM_data2 ||
                    ab->form[i] == DWARF_FORM_data4 ||
                    ab->form[i] == DWARF_FORM_data8)) {
            array_upper = (int)read_attr_number(ab->form[i],
                                                debug_info + attr_off);
        }

        skip_attr(ab->form[i], ab->implicit[i],
                  debug_info, debug_info_size, &die_off);
    }

    switch (ab->tag) {
    case DW_TAG_base_type:
        ti.kind = TYPE_BASE;
        if (ti.size == 0)
            ti.size = 4;
        break;
    case DW_TAG_pointer_type:
        ti.kind = TYPE_POINTER;
        ti.ref_off = ref_type;
        if (ti.size == 0)
            ti.size = dwarf_addr_size;
        break;
    case DW_TAG_structure_type:
        ti.kind = TYPE_STRUCT;
        if (ab->has_children) {
            size_t child_off = die_off;
            parse_struct_members(&child_off, debug_info_size, &ti);
        }
        break;
    case DW_TAG_array_type:
        ti.kind = TYPE_ARRAY;
        ti.ref_off = ref_type;
        ti.elem_type_off = ref_type;
        if (ab->has_children) {
            size_t child_off = die_off;

            while (child_off < debug_info_size) {
                uint64_t subcode =
                    read_uleb128(debug_info, debug_info_size, &child_off);

                if (subcode == 0)
                    break;

                dwarf_abbrev_t *sub = find_abbrev(subcode);

                if (!sub)
                    break;

                for (int j = 0; j < sub->nattr; j++) {
                    size_t attr_off = child_off;

                    if (sub->attr[j] == DW_AT_upper_bound &&
                        (sub->form[j] == DWARF_FORM_data1 ||
                         sub->form[j] == DWARF_FORM_data2 ||
                         sub->form[j] == DWARF_FORM_data4 ||
                         sub->form[j] == DWARF_FORM_data8)) {
                        array_upper =
                            (int)read_attr_number(sub->form[j],
                                                  debug_info + attr_off);
                    }

                    skip_attr(sub->form[j], sub->implicit[j],
                              debug_info, debug_info_size, &child_off);
                }
            }
        }

        if (array_upper >= 0)
            ti.array_count = array_upper + 1;
        break;
    case DW_TAG_typedef:
    case DW_TAG_const_type:
        if (ref_type) {
            if (get_type_info(ref_type, &ti) != 0)
                return -1;
            ti.kind = TYPE_ALIAS;
            ti.ref_off = ref_type;
        }
        break;
    default:
        break;
    }

    if (ti.kind == TYPE_ARRAY && ti.ref_off) {
        type_info_t elem;

        if (get_type_info(ti.ref_off, &elem) == 0)
            ti.size = elem.size * (size_t)ti.array_count;
    }

    cache_type(off, &ti);
    *out = ti;
    return 0;
}

static int get_type_info(uint32_t off, type_info_t *out)
{
    if (type_cache_lookup(off, out) == 0)
        return 0;

    return parse_type_die(off, out);
}

static void resolve_type_alias(type_info_t *ti, uint32_t *orig_off)
{
    int depth = 0;

    while (ti->kind == TYPE_ALIAS && ti->ref_off && depth < 8) {
        if (*orig_off == 0)
            *orig_off = ti->ref_off;

        type_info_t next;

        if (get_cached_type(ti->ref_off, &next) != 0)
            break;

        *ti = next;
        depth++;
    }
}

static void preload_types(void)
{
    for (int i = 0; i < var_count; i++) {
        if (!vars[i].type_off)
            continue;

        type_info_t ti;

        get_type_info(vars[i].type_off, &ti);
    }
}

static void parse_dies(size_t *off,
                       size_t unit_end,
                       unsigned long scope_low,
                       unsigned long scope_high)
{
    while (*off < unit_end) {
        uint64_t abcode = read_uleb128(debug_info, unit_end, off);

        if (abcode == 0)
            return;

        dwarf_abbrev_t *ab = find_abbrev(abcode);

        if (!ab)
            continue;

        char name[64] = {0};
        const uint8_t *loc = NULL;
        size_t loc_len = 0;
        unsigned long low_pc = 0;
        unsigned long high_pc = 0;
        int has_low = 0;
        int has_high = 0;
        uint32_t type_off = 0;

        for (int i = 0; i < ab->nattr; i++) {
            size_t attr_off = *off;

            if (ab->form[i] == DWARF_FORM_string) {
                const char *s = read_attr_string(ab->form[i], ab->implicit[i],
                                                 debug_info, debug_info_size,
                                                 &attr_off);
                if (ab->attr[i] == DW_AT_name && s)
                    strncpy(name, s, sizeof(name) - 1);
            } else if (ab->form[i] == DWARF_FORM_strp &&
                       ab->attr[i] == DW_AT_name) {
                const char *s = read_attr_string(ab->form[i], 0,
                                                 debug_info, debug_info_size,
                                                 &attr_off);
                if (s)
                    strncpy(name, s, sizeof(name) - 1);
            } else if (ab->form[i] == DWARF_FORM_addr &&
                       ab->attr[i] == DW_AT_low_pc) {
                low_pc = 0;
                for (int b = 0; b < dwarf_addr_size; b++)
                    low_pc |= (unsigned long)debug_info[attr_off + b]
                              << (8 * b);
                has_low = 1;
            } else if (ab->form[i] == DWARF_FORM_data8 &&
                       ab->attr[i] == DW_AT_high_pc) {
                high_pc = *(uint64_t *)(debug_info + attr_off);
                has_high = 1;
            } else if (ab->attr[i] == DW_AT_location) {
                if (ab->form[i] == DWARF_FORM_exprloc) {
                    size_t tmp = attr_off;
                    loc_len = read_uleb128(debug_info, debug_info_size, &tmp);
                    loc = debug_info + tmp;
                } else if (ab->form[i] == DWARF_FORM_block1 &&
                           attr_off < unit_end) {
                    loc_len = debug_info[attr_off];
                    loc = debug_info + attr_off + 1;
                }
            } else if (ab->attr[i] == DW_AT_type &&
                       ab->form[i] == DWARF_FORM_ref4) {
                uint32_t ref = *(uint32_t *)(debug_info + attr_off);
                type_off = (uint32_t)(current_cu_base + ref);
            }

            skip_attr(ab->form[i], ab->implicit[i],
                      debug_info, unit_end, off);
        }

        unsigned long child_low = scope_low;
        unsigned long child_high = scope_high;

        if (has_low) {
            child_low = low_pc;
            child_high = has_high ? low_pc + high_pc : scope_high;
        }

        if ((ab->tag == DW_TAG_variable ||
             ab->tag == DW_TAG_formal_parameter) &&
            name[0] && loc && loc_len > 0) {
            add_var_entry(name, scope_low, scope_high, loc, loc_len,
                          type_off);
        }

        if (ab->has_children)
            parse_dies(off, unit_end, child_low, child_high);
    }
}

void load_variables(char *path)
{
    var_count = 0;

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return;
    }

    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (map == MAP_FAILED)
        return;

    Elf64_Ehdr *ehdr = map;
    Elf64_Shdr *shdrs =
        (Elf64_Shdr *)((char *)map + ehdr->e_shoff);
    char *shstr =
        (char *)map + shdrs[ehdr->e_shstrndx].sh_offset;

    const uint8_t *debug_abbrev = NULL;
    size_t debug_abbrev_size = 0;

    debug_info = NULL;
    debug_info_size = 0;
    debug_str = NULL;
    debug_str_size = 0;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *name = shstr + shdrs[i].sh_name;

        if (!strcmp(name, ".debug_info")) {
            debug_info =
                (const uint8_t *)map + shdrs[i].sh_offset;
            debug_info_size = shdrs[i].sh_size;
        } else if (!strcmp(name, ".debug_abbrev")) {
            debug_abbrev =
                (const uint8_t *)map + shdrs[i].sh_offset;
            debug_abbrev_size = shdrs[i].sh_size;
        } else if (!strcmp(name, ".debug_str")) {
            debug_str =
                (const uint8_t *)map + shdrs[i].sh_offset;
            debug_str_size = shdrs[i].sh_size;
        }
    }

    if (!debug_info || !debug_abbrev)
        goto out;

    load_abbrev_table(debug_abbrev, debug_abbrev_size);

    size_t off = 0;

    while (off + 4 <= debug_info_size) {
        size_t cu_base = off;
        uint32_t unit_length =
            *(uint32_t *)(debug_info + off);

        if (unit_length == 0xffffffff)
            break;

        size_t unit_end = off + 4 + unit_length;

        off += 4;
        off += 2;
        off += 1;
        dwarf_addr_size = debug_info[off++];
        read_uleb128(debug_info, debug_info_size, &off);

        while (off < unit_end) {
            size_t tmp = off;
            uint64_t peek = read_uleb128(debug_info, unit_end, &tmp);

            if (peek != 0)
                break;

            off++;
        }

        current_cu_base = cu_base;
        parse_dies(&off, unit_end, 0, ~0UL);
        off = unit_end;
    }

    preload_types();

out:
    munmap(map, st.st_size);
    debug_info = NULL;
    debug_info_size = 0;
    debug_str = NULL;
    debug_str_size = 0;
}

static var_entry_t *lookup_var(const char *name, unsigned long rip)
{
    var_entry_t *best = NULL;
    unsigned long best_size = ~0UL;

    rip = to_debug_addr(rip);

    for (int i = 0; i < var_count; i++) {
        if (strcmp(vars[i].name, name))
            continue;

        if (rip < vars[i].scope_low || rip >= vars[i].scope_high)
            continue;

        unsigned long size = vars[i].scope_high - vars[i].scope_low;

        if (size < best_size) {
            best_size = size;
            best = &vars[i];
        }
    }

    return best;
}

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

static int parse_on_off(const char *name, int *value)
{
    if (!strcmp(name, "on") || !strcmp(name, "1") || !strcmp(name, "yes")) {
        *value = 1;
        return 0;
    }

    if (!strcmp(name, "off") || !strcmp(name, "0") || !strcmp(name, "no")) {
        *value = 0;
        return 0;
    }

    return -1;
}

static void trim_line(char *s)
{
    size_t len = strlen(s);

    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' ||
                       s[len - 1] == ' ' || s[len - 1] == '\t')) {
        s[--len] = '\0';
    }
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

static int read_target_byte(unsigned long addr, unsigned char *out)
{
    unsigned long aligned = addr & ~(unsigned long)(sizeof(long) - 1);
    long word = read_memory(aligned);

    if (word == -1)
        return -1;

    *out = (unsigned char)(word >> (8 * (addr - aligned)));
    return 0;
}

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

static int poke_word(unsigned long addr, unsigned long value)
{
    errno = 0;

    if (ptrace(PTRACE_POKEDATA, dbg.pid, (void *)addr,
               (void *)value) == -1) {
        perror("ptrace poke");
        return -1;
    }

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

#define DW_LNS_extended_op      0x00
#define DW_LNS_copy             0x01
#define DW_LNS_advance_pc       0x02
#define DW_LNS_advance_line     0x03
#define DW_LNS_set_file         0x04
#define DW_LNS_set_column       0x05
#define DW_LNS_negate_stmt      0x06
#define DW_LNS_set_basic_block  0x07
#define DW_LNS_const_add_pc     0x08
#define DW_LNS_fixed_advance_pc 0x09

#define DW_LNE_end_sequence     0x01
#define DW_LNE_set_address      0x02

#define DW_LNCT_path            0x0001
#define DW_LNCT_directory_index 0x000f
#define DW_FORM_line_strp       0x1f
#define DW_FORM_data1           0x01

static uint64_t read_uleb128(const uint8_t *data, size_t len, size_t *off)
{
    uint64_t result = 0;
    unsigned int shift = 0;

    while (*off < len) {
        uint8_t byte = data[(*off)++];
        result |= (uint64_t)(byte & 0x7f) << shift;
        if ((byte & 0x80) == 0)
            return result;
        shift += 7;
    }

    return result;
}

static int64_t read_sleb128(const uint8_t *data, size_t len, size_t *off)
{
    uint64_t result = 0;
    unsigned int shift = 0;

    while (*off < len) {
        uint8_t byte = data[(*off)++];
        result |= (uint64_t)(byte & 0x7f) << shift;
        if ((byte & 0x80) == 0) {
            if (shift < 64 && (byte & 0x40))
                result |= -(1ULL << (shift + 7));
            return (int64_t)result;
        }
        shift += 7;
    }

    return 0;
}

static const char *line_strp(const uint8_t *line_str,
                             size_t line_str_size,
                             uint32_t offset)
{
    if (offset >= line_str_size)
        return "";

    return (const char *)(line_str + offset);
}

static void line_entry_add(unsigned long addr,
                           const char *file,
                           int line)
{
    if (line_entry_count >= MAX_LINE_ENTRIES)
        return;

    line_entry_t *ent = &line_entries[line_entry_count++];

    ent->addr = addr;
    ent->line = line;
    strncpy(ent->file, file, sizeof(ent->file) - 1);
    ent->file[sizeof(ent->file) - 1] = '\0';
}

static void resolve_file_path(char *out,
                            size_t out_size,
                            const char * const *dirs,
                            int dir_count,
                            const char * const *files,
                            const int *file_dirs,
                            int file_count,
                            int file_index)
{
    if (file_index < 0 || file_index >= file_count) {
        snprintf(out, out_size, "??");
        return;
    }

    const char *name = files[file_index];
    int dir_index = file_dirs[file_index];

    if (dir_index >= 0 && dir_index < dir_count &&
        dirs[dir_index][0] != '\0') {
        snprintf(out, out_size, "%s/%s",
                 dirs[dir_index], name);
    } else {
        snprintf(out, out_size, "%s", name);
    }
}

static void parse_line_program(const uint8_t *data,
                               size_t len,
                               size_t prog_off,
                               size_t prog_end,
                               const char * const *dirs,
                               int dir_count,
                               const char * const *files,
                               const int *file_dirs,
                               int file_count,
                               uint8_t min_inst_len,
                               int8_t line_base,
                               uint8_t line_range,
                               uint8_t opcode_base,
                               const uint8_t *std_lengths)
{
    unsigned long address = 0;
    int line = 1;
    int file_index = 0;
    char file_path[512];

    size_t off = prog_off;

    while (off < prog_end && off < len) {
        uint8_t opcode = data[off++];

        if (opcode >= opcode_base) {
            uint8_t adjusted = opcode - opcode_base;
            unsigned long addr_adv =
                min_inst_len * (adjusted / line_range);
            int line_adv =
                line_base + (adjusted % line_range);

            address += addr_adv;
            line += line_adv;

            resolve_file_path(file_path, sizeof(file_path),
                              dirs, dir_count,
                              files, file_dirs, file_count,
                              file_index);
            line_entry_add(address, file_path, line);
            continue;
        }

        if (opcode == DW_LNS_extended_op) {
            uint64_t ext_len = read_uleb128(data, len, &off);
            size_t ext_start = off;

            if (off >= len)
                break;

            uint8_t ext_op = data[off++];

            if (ext_op == DW_LNE_end_sequence) {
                resolve_file_path(file_path, sizeof(file_path),
                                  dirs, dir_count,
                                  files, file_dirs, file_count,
                                  file_index);
                line_entry_add(address, file_path, line);
                address = 0;
                file_index = 0;
                line = 1;
            } else if (ext_op == DW_LNE_set_address) {
                address = 0;
                for (uint64_t i = 0;
                     i < ext_len - 1 && off < len;
                     i++) {
                    address |=
                        (unsigned long)data[off++]
                        << (8 * i);
                }
            } else {
                off = ext_start + ext_len;
            }

            continue;
        }

        switch (opcode) {
        case DW_LNS_copy:
            resolve_file_path(file_path, sizeof(file_path),
                              dirs, dir_count,
                              files, file_dirs, file_count,
                              file_index);
            line_entry_add(address, file_path, line);
            break;

        case DW_LNS_advance_pc:
            address +=
                min_inst_len *
                read_uleb128(data, len, &off);
            break;

        case DW_LNS_advance_line:
            line += (int)read_sleb128(data, len, &off);
            break;

        case DW_LNS_set_file:
            file_index =
                (int)read_uleb128(data, len, &off);
            break;

        case DW_LNS_set_column:
            read_uleb128(data, len, &off);
            break;

        case DW_LNS_negate_stmt:
        case DW_LNS_set_basic_block:
            break;

        case DW_LNS_const_add_pc:
            address +=
                min_inst_len *
                ((255 - opcode_base) / line_range);
            break;

        case DW_LNS_fixed_advance_pc: {
            uint16_t adv = data[off] | (data[off + 1] << 8);
            off += 2;
            address += adv;
            break;
        }

        default:
            if (opcode > 0 && opcode < opcode_base) {
                for (uint8_t i = 0;
                     i < std_lengths[opcode - 1] && off < len;
                     i++)
                    read_uleb128(data, len, &off);
            }
            break;
        }
    }
}

static void parse_line_table_unit(const uint8_t *data,
                                  size_t len,
                                  size_t *off,
                                  const uint8_t *line_str,
                                  size_t line_str_size)
{
    if (*off + 4 > len)
        return;

    uint32_t unit_length =
        *(uint32_t *)(data + *off);

  if (unit_length == 0xffffffff) {
        return;
    }

    size_t unit_start = *off;
    size_t unit_end = unit_start + 4 + unit_length;

    if (unit_end > len)
        return;

    *off += 4;

    uint16_t version = *(uint16_t *)(data + *off);
    *off += 2;

    if (version != 5)
        return;

    uint8_t address_size = data[(*off)++];
    (void)address_size;
    uint8_t segment_size = data[(*off)++];
    (void)segment_size;

    uint32_t header_length =
        *(uint32_t *)(data + *off);
    *off += 4;

    size_t header_start = *off;
    size_t prog_off = header_start + header_length;

    if (prog_off > unit_end)
        return;

    uint8_t min_inst_len = data[(*off)++];
    uint8_t max_ops = data[(*off)++];
    (void)max_ops;
    uint8_t default_is_stmt = data[(*off)++];
    (void)default_is_stmt;
    int8_t line_base = (int8_t)data[(*off)++];
    uint8_t line_range = data[(*off)++];
    uint8_t opcode_base = data[(*off)++];

    uint8_t std_lengths[12];
    for (uint8_t i = 1; i < opcode_base && i <= 12; i++)
        std_lengths[i - 1] = data[(*off)++];

    int dir_count = 0;
    const char *dirs[64];

    uint64_t dir_fmt_count = read_uleb128(data, unit_end, off);
    uint64_t dir_form_types[8];
    uint64_t dir_form_forms[8];

    for (uint64_t i = 0; i < dir_fmt_count && i < 8; i++) {
        dir_form_types[i] = read_uleb128(data, unit_end, off);
        dir_form_forms[i] = read_uleb128(data, unit_end, off);
    }

    uint64_t directories_count = read_uleb128(data, unit_end, off);
    for (uint64_t d = 0; d < directories_count && d < 64; d++) {
        for (uint64_t i = 0; i < dir_fmt_count; i++) {
            if (dir_form_types[i] == DW_LNCT_path &&
                dir_form_forms[i] == DW_FORM_line_strp) {
                uint32_t strp_off =
                    *(uint32_t *)(data + *off);
                *off += 4;
                dirs[dir_count++] =
                    line_strp(line_str, line_str_size, strp_off);
            } else {
                read_uleb128(data, unit_end, off);
            }
        }
    }

    int file_count = 0;
    const char *files[256];
    int file_dirs[256];

    uint64_t file_fmt_count = read_uleb128(data, unit_end, off);
    uint64_t file_form_types[8];
    uint64_t file_form_forms[8];

    for (uint64_t i = 0; i < file_fmt_count && i < 8; i++) {
        file_form_types[i] = read_uleb128(data, unit_end, off);
        file_form_forms[i] = read_uleb128(data, unit_end, off);
    }

    uint64_t file_names_count = read_uleb128(data, unit_end, off);
    for (uint64_t f = 0; f < file_names_count && f < 256; f++) {
        const char *fname = "??";
        int fdir = 0;

        for (uint64_t i = 0; i < file_fmt_count; i++) {
            if (file_form_types[i] == DW_LNCT_path &&
                file_form_forms[i] == DW_FORM_line_strp) {
                uint32_t strp_off =
                    *(uint32_t *)(data + *off);
                *off += 4;
                fname = line_strp(line_str, line_str_size, strp_off);
            } else if (file_form_types[i] ==
                       DW_LNCT_directory_index) {
                fdir = (int)read_uleb128(data, unit_end, off);
            } else if (file_form_forms[i] == DW_FORM_data1) {
                fdir = data[(*off)++];
            } else {
                read_uleb128(data, unit_end, off);
            }
        }

        files[file_count] = fname;
        file_dirs[file_count] = fdir;
        file_count++;
    }

    *off = prog_off;

    parse_line_program(data, len, prog_off, unit_end,
                       dirs, dir_count,
                       files, file_dirs, file_count,
                       min_inst_len, line_base, line_range,
                       opcode_base, std_lengths);

    *off = unit_end;
}

static int line_entry_cmp(const void *a, const void *b)
{
    const line_entry_t *ea = a;
    const line_entry_t *eb = b;

    if (ea->addr < eb->addr)
        return -1;
    if (ea->addr > eb->addr)
        return 1;
    return 0;
}

void load_line_table(char *path)
{
    line_entry_count = 0;
    line_addr_min = 0;
    line_addr_max = 0;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return;
    }

    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (map == MAP_FAILED) {
        perror("mmap");
        return;
    }

    Elf64_Ehdr *ehdr = map;
    Elf64_Shdr *shdrs =
        (Elf64_Shdr *)((char *)map + ehdr->e_shoff);
    char *shstr =
        (char *)map + shdrs[ehdr->e_shstrndx].sh_offset;

    const uint8_t *debug_line = NULL;
    size_t debug_line_size = 0;
    const uint8_t *debug_line_str = NULL;
    size_t debug_line_str_size = 0;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *name = shstr + shdrs[i].sh_name;

        if (!strcmp(name, ".debug_line")) {
            debug_line =
                (const uint8_t *)map + shdrs[i].sh_offset;
            debug_line_size = shdrs[i].sh_size;
        } else if (!strcmp(name, ".debug_line_str")) {
            debug_line_str =
                (const uint8_t *)map + shdrs[i].sh_offset;
            debug_line_str_size = shdrs[i].sh_size;
        }
    }

    if (!debug_line || !debug_line_str) {
        munmap(map, st.st_size);
        return;
    }

    size_t off = 0;
    while (off < debug_line_size)
        parse_line_table_unit(debug_line, debug_line_size, &off,
                              debug_line_str, debug_line_str_size);

    qsort(line_entries, line_entry_count,
          sizeof(line_entry_t), line_entry_cmp);

    if (line_entry_count > 0) {
        line_addr_min = line_entries[0].addr;
        line_addr_max = line_entries[line_entry_count - 1].addr;
    }

    munmap(map, st.st_size);
}

int lookup_line(unsigned long addr, const char **file, int *line)
{
    if (line_entry_count == 0)
        return -1;

    addr = to_debug_addr(addr);

    if (addr < line_addr_min || addr > line_addr_max)
        return -1;

    int lo = 0;
    int hi = line_entry_count - 1;
    int best = -1;

    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;

        if (line_entries[mid].addr <= addr) {
            best = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }

    if (best < 0)
        return -1;

    if (best + 1 < line_entry_count &&
        addr >= line_entries[best + 1].addr)
        return -1;

    *file = line_entries[best].file;
    *line = line_entries[best].line;
    return 0;
}

static const char *file_basename(const char *path)
{
    const char *slash = strrchr(path, '/');

    return slash ? slash + 1 : path;
}

static int file_matches(const char *entry_file, const char *query)
{
    if (!strcmp(entry_file, query))
        return 1;

    if (!strcmp(file_basename(entry_file), query))
        return 1;

    return 0;
}

static unsigned long to_debug_addr(unsigned long addr)
{
    if (dbg.is_pie && dbg.load_base != 0 && addr >= dbg.load_base)
        return addr - dbg.load_base;

    return addr;
}

static unsigned long to_runtime_addr(unsigned long addr)
{
    if (dbg.is_pie && dbg.load_base != 0 && addr < dbg.load_base)
        return addr + dbg.load_base;

    return addr;
}

static int map_path_matches_debuggee(const char *path)
{
    if (!path || !path[0])
        return 0;

    if (!strcmp(path, debuggee_realpath))
        return 1;

    if (!strcmp(file_basename(path), file_basename(debuggee_realpath)))
        return 1;

    return 0;
}

static int update_load_base(void)
{
    dbg.load_base = 0;

    if (!dbg.is_pie)
        return 0;

    char maps_path[64];

    snprintf(maps_path, sizeof(maps_path),
             "/proc/%d/maps", dbg.pid);

    FILE *fp = fopen(maps_path, "r");

    if (!fp) {
        perror("fopen maps");
        return -1;
    }

    char line[1024];

    while (fgets(line, sizeof(line), fp)) {
        unsigned long start;
        unsigned long end;
        unsigned long offset;
        char perms[5] = {0};
        char path[512] = {0};

        int n = sscanf(line,
                       "%lx-%lx %4s %lx %*s %*s %511s",
                       &start, &end, perms, &offset, path);

        if (n < 4)
            continue;

        if (n == 5 && strchr(perms, 'x') &&
            map_path_matches_debuggee(path)) {
            dbg.load_base = start - offset;
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

int lookup_line_addr(const char *file, int line, unsigned long *addr)
{
    unsigned long best = 0;
    int found = 0;

    for (int i = 0; i < line_entry_count; i++) {
        if (line_entries[i].line != line)
            continue;

        if (!file_matches(line_entries[i].file, file))
            continue;

        if (!found || line_entries[i].addr < best) {
            best = line_entries[i].addr;
            found = 1;
        }
    }

    if (!found)
        return -1;

    *addr = best;
    return 0;
}

int lookup_next_line(const char *file,
                     int line,
                     int *next_line,
                     unsigned long *addr)
{
    int found_line = -1;
    unsigned long found_addr = 0;

    for (int i = 0; i < line_entry_count; i++) {
        if (!file_matches(line_entries[i].file, file))
            continue;

        if (line_entries[i].line <= line)
            continue;

        if (found_line < 0 ||
            line_entries[i].line < found_line) {
            found_line = line_entries[i].line;
            found_addr = line_entries[i].addr;
        } else if (line_entries[i].line == found_line &&
                   line_entries[i].addr < found_addr) {
            found_addr = line_entries[i].addr;
        }
    }

    if (found_line < 0)
        return -1;

    *next_line = found_line;
    *addr = found_addr;
    return 0;
}

int get_return_address(unsigned long *ret_addr);

static unsigned long current_func_start(unsigned long rip)
{
    rip = to_debug_addr(rip);

    unsigned long start = 0;

    for (int i = 0; i < sym_count; i++) {
        if (symbols[i].type == STT_FUNC &&
            symbols[i].addr <= rip &&
            symbols[i].addr >= start) {
            start = symbols[i].addr;
        }
    }

    return start;
}

static unsigned long current_func_end(unsigned long rip)
{
    unsigned long start = current_func_start(rip);
    unsigned long end = 0;

    for (int i = 0; i < sym_count; i++) {
        if (symbols[i].type == STT_FUNC &&
            symbols[i].addr > start &&
            (end == 0 || symbols[i].addr < end)) {
            end = symbols[i].addr;
        }
    }

    if (end == 0)
        end = line_addr_max + 1;

    return end;
}

int lookup_next_line_scoped(unsigned long rip,
                            const char *file,
                            int line,
                            int *next_line,
                            unsigned long *addr)
{
    unsigned long debug_rip = to_debug_addr(rip);
    unsigned long func_end = current_func_end(rip);
    unsigned long best = 0;
    int best_line = 0;

    for (int i = 0; i < line_entry_count; i++) {
        if (line_entries[i].addr <= debug_rip)
            continue;

        if (line_entries[i].addr >= func_end)
            continue;

        if (line_entries[i].line <= line)
            continue;

        if (!file_matches(line_entries[i].file, file))
            continue;

        if (best == 0 ||
            line_entries[i].line < best_line ||
            (line_entries[i].line == best_line &&
             line_entries[i].addr < best)) {
            best = line_entries[i].addr;
            best_line = line_entries[i].line;
        }
    }

    if (best != 0) {
        *addr = to_runtime_addr(best);
        *next_line = best_line;
        return 0;
    }

    if (get_return_address(addr) != 0)
        return -1;

    if (lookup_line(*addr, &file, &line) == 0)
        *next_line = line;
    else
        *next_line = 0;

    return 0;
}

#define SOURCE_CONTEXT 5

int show_source_listing(const char *file, int line)
{
    FILE *fp = fopen(file, "r");

    if (!fp)
        return -1;

    char buf[1024];
    int cur = 0;
    int start = line - SOURCE_CONTEXT;
    int found = 0;

    if (start < 1)
        start = 1;

    int end = line + SOURCE_CONTEXT;

    while (fgets(buf, sizeof(buf), fp)) {
        cur++;

        if (cur < start)
            continue;

        if (cur > end)
            break;

        size_t len = strlen(buf);

        if (len > 0 && buf[len - 1] == '\n')
            buf[len - 1] = '\0';

        if (cur == line)
            found = 1;

        if (cur == line)
            printf("=> %4d  %s\n", cur, buf);
        else
            printf("   %4d  %s\n", cur, buf);
    }

    fclose(fp);
    return found ? 0 : -1;
}

static const char *resolve_source_file(const char *query)
{
    for (int i = 0; i < line_entry_count; i++) {
        if (file_matches(line_entries[i].file, query))
            return line_entries[i].file;
    }

    return query;
}

static const char *current_source_file(void)
{
    if (dbg.running) {
        struct user_regs_struct regs;
        const char *file;
        int line;

        if (ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs) == 0 &&
            lookup_line(regs.rip, &file, &line) == 0)
            return file;
    }

    if (line_entry_count > 0)
        return line_entries[0].file;

    return NULL;
}

static void list_source_at(const char *file, int line)
{
    if (!file || line <= 0) {
        printf("no line info\n");
        return;
    }

    printf("=> %s:%d\n", file, line);
    show_source_listing(file, line);
}

void list_source(const char *arg)
{
    if (line_entry_count == 0) {
        printf("no line info (use run first)\n");
        return;
    }

    char item[256];

    if (sscanf(arg, "%255s", item) != 1) {
        const char *file;
        int line;

        if (dbg.running) {
            struct user_regs_struct regs;

            if (ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs) == 0 &&
                lookup_line(regs.rip, &file, &line) == 0) {
                list_source_at(file, line);
                return;
            }
        }

        printf("usage: l|list <line|file:line|function>\n");
        return;
    }

    char *colon = strrchr(item, ':');

    if (colon && colon[1] != '\0') {
        char file[256];
        size_t file_len = colon - item;

        if (file_len >= sizeof(file)) {
            printf("invalid location: %s\n", item);
            return;
        }

        memcpy(file, item, file_len);
        file[file_len] = '\0';

        char *end;
        long line_num = strtol(colon + 1, &end, 10);

        if (*end == '\0' && line_num > 0) {
            list_source_at(resolve_source_file(file), (int)line_num);
            return;
        }
    }

    char *end;
    long line_num = strtol(item, &end, 10);

    if (*end == '\0' && end != item && line_num > 0) {
        const char *file = current_source_file();

        if (!file) {
            printf("no current source file\n");
            return;
        }

        list_source_at(file, (int)line_num);
        return;
    }

    unsigned long addr;

    if (lookup_symbol(item, &addr) == 0) {
        const char *file;
        int line;

        if (lookup_line(addr, &file, &line) == 0) {
            list_source_at(file, line);
            return;
        }
    }

    printf("unknown source location: %s\n", item);
}

static void show_disassembly_line(unsigned long addr)
{
    if (debuggee_path[0] == '\0') {
        printf("=> 0x%lx\n", addr);
        return;
    }

    unsigned long debug_addr = to_debug_addr(addr);
    char cmd[1024];

    snprintf(cmd, sizeof(cmd),
             "objdump -d --start-address=0x%lx "
             "--stop-address=0x%lx '%s'",
             debug_addr, debug_addr + 16, debuggee_path);

    FILE *fp = popen(cmd, "r");

    if (!fp) {
        perror("popen");
        printf("=> 0x%lx\n", addr);
        return;
    }

    char buf[1024];

    while (fgets(buf, sizeof(buf), fp)) {
        char *p = buf;

        while (*p == ' ' || *p == '\t')
            p++;

        char *end;
        unsigned long insn_addr = strtoul(p, &end, 16);

        if (end == p || *end != ':')
            continue;

        char *text = end + 1;
        size_t len = strlen(text);

        if (len > 0 && text[len - 1] == '\n')
            text[len - 1] = '\0';

        printf("=> 0x%lx:%s\n",
               to_runtime_addr(insn_addr),
               text);
        pclose(fp);
        return;
    }

    pclose(fp);
    printf("=> 0x%lx\n", addr);
}

static void show_stop_location(unsigned long pc)
{
    const char *file;
    int line;

    if (lookup_line(pc, &file, &line) == 0) {
        printf("=> %s:%d\n", file, line);

        if (show_source_listing(file, line) == 0)
            return;
    }

    show_disassembly_line(pc);
}

void show_pc_location(unsigned long rip)
{
    show_stop_location(rip);
}

void load_symbols(char *path)
{
    sym_count = 0;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return;
    }

    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (map == MAP_FAILED) {
        perror("mmap");
        return;
    }

    Elf64_Ehdr *ehdr = map;
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        fprintf(stderr, "not an ELF file\n");
        munmap(map, st.st_size);
        return;
    }

    dbg.is_pie = (ehdr->e_type == ET_DYN);

    Elf64_Shdr *shdrs =
        (Elf64_Shdr *)((char *)map + ehdr->e_shoff);

    Elf64_Shdr *symtab = NULL;
    Elf64_Shdr *strtab = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            symtab = &shdrs[i];
            strtab = &shdrs[symtab->sh_link];
            break;
        }
    }

    if (!symtab || !strtab) {
        munmap(map, st.st_size);
        return;
    }

    Elf64_Sym *syms =
        (Elf64_Sym *)((char *)map + symtab->sh_offset);
    char *strs = (char *)map + strtab->sh_offset;
    int count = symtab->sh_size / sizeof(Elf64_Sym);

    for (int i = 0; i < count && sym_count < MAX_SYMBOLS; i++) {
        Elf64_Sym *sym = &syms[i];
        unsigned char type = ELF64_ST_TYPE(sym->st_info);

        if (type != STT_FUNC && type != STT_OBJECT)
            continue;

        if (sym->st_shndx == SHN_UNDEF || sym->st_value == 0)
            continue;

        if (sym->st_name == 0)
            continue;

        strncpy(symbols[sym_count].name,
                strs + sym->st_name,
                sizeof(symbols[sym_count].name) - 1);
        symbols[sym_count].name[
            sizeof(symbols[sym_count].name) - 1] = '\0';
        symbols[sym_count].addr = sym->st_value;
        symbols[sym_count].size = sym->st_size;
        symbols[sym_count].type = type;
        sym_count++;
    }

    munmap(map, st.st_size);
}

void show_symbols(void)
{
    if (sym_count == 0) {
        printf("no symbols loaded (use run first)\n");
        return;
    }

    for (int i = 0; i < sym_count; i++) {
        const char *kind =
            symbols[i].type == STT_FUNC ? "func" : "obj";

        printf("0x%lx %-4s %s\n",
               symbols[i].addr,
               kind,
               symbols[i].name);
    }
}

static const symbol_t *lookup_symbol_entry(const char *name)
{
    for (int i = 0; i < sym_count; i++) {
        if (!strcmp(symbols[i].name, name))
            return &symbols[i];
    }

    return NULL;
}

int lookup_symbol(const char *name, unsigned long *addr)
{
    const symbol_t *sym = lookup_symbol_entry(name);

    if (!sym)
        return -1;

    *addr = sym->addr;
    return 0;
}

static int lookup_function_body_addr(const symbol_t *sym,
                                     unsigned long *addr)
{
    if (!sym || sym->type != STT_FUNC)
        return -1;

    unsigned long start = sym->addr;
    unsigned long end = sym->size ? start + sym->size : 0;
    unsigned long best = 0;

    for (int i = 0; i < line_entry_count; i++) {
        unsigned long line_addr = line_entries[i].addr;

        if (line_addr <= start)
            continue;

        if (end != 0 && line_addr >= end)
            continue;

        if (best == 0 || line_addr < best)
            best = line_addr;
    }

    if (best == 0)
        return -1;

    *addr = best;
    return 0;
}

static const symbol_t *lookup_function_symbol(unsigned long addr)
{
    const symbol_t *best = NULL;

    addr = to_debug_addr(addr);

    for (int i = 0; i < sym_count; i++) {
        if (symbols[i].type != STT_FUNC)
            continue;

        if (symbols[i].addr > addr)
            continue;

        if (symbols[i].size > 0 &&
            addr >= symbols[i].addr + symbols[i].size)
            continue;

        if (symbols[i].size == 0 &&
            addr != symbols[i].addr)
            continue;

        if (!best || symbols[i].addr > best->addr)
            best = &symbols[i];
    }

    return best;
}

static void disassemble_range(unsigned long start, unsigned long end)
{
    if (debuggee_path[0] == '\0') {
        printf("no program loaded (use run first)\n");
        return;
    }

    start = to_debug_addr(start);
    end = to_debug_addr(end);

    if (end <= start)
        end = start + 64;

    char cmd[1024];

    snprintf(cmd, sizeof(cmd),
             "objdump -d --start-address=0x%lx "
             "--stop-address=0x%lx '%s'",
             start, end, debuggee_path);

    FILE *fp = popen(cmd, "r");

    if (!fp) {
        perror("popen");
        return;
    }

    char buf[1024];

    while (fgets(buf, sizeof(buf), fp))
        fputs(buf, stdout);

    pclose(fp);
}

static unsigned long disassemble_line_end(unsigned long start)
{
    unsigned long end = 0;

    for (int i = 0; i < line_entry_count; i++) {
        if (line_entries[i].addr <= start)
            continue;

        if (end == 0 || line_entries[i].addr < end)
            end = line_entries[i].addr;
    }

    if (end == 0 || end <= start)
        end = start + 64;

    return end;
}

static int disassemble_line_location(const char *file,
                                     int line)
{
    unsigned long addr;

    if (lookup_line_addr(file, line, &addr) != 0)
        return -1;

    disassemble_range(addr, disassemble_line_end(addr));
    return 0;
}

void disassemble_command(const char *arg)
{
    if (debuggee_path[0] == '\0') {
        printf("no program loaded (use run first)\n");
        return;
    }

    char item[256];

    if (sscanf(arg, "%255s", item) != 1) {
        printf("usage: dis <function|file:line|line|addr>\n");
        return;
    }

    char *colon = strrchr(item, ':');

    if (colon && colon[1] != '\0') {
        char file[256];
        size_t file_len = colon - item;

        if (file_len >= sizeof(file)) {
            printf("invalid location: %s\n", item);
            return;
        }

        memcpy(file, item, file_len);
        file[file_len] = '\0';

        char *end;
        long line_num = strtol(colon + 1, &end, 10);

        if (*end == '\0' && line_num > 0) {
            if (disassemble_line_location(file, (int)line_num) != 0)
                printf("no line info for %s:%ld\n",
                       file, line_num);
            return;
        }
    }

    char *end;
    unsigned long value = strtoul(item, &end, 0);

    if (*end == '\0' && end != item && value > 0) {
        const char *file = current_source_file();
        int handled_as_line = 0;

        if (strncmp(item, "0x", 2) && strncmp(item, "0X", 2) && file) {
            if (disassemble_line_location(file, (int)value) == 0)
                handled_as_line = 1;
        }

        if (!handled_as_line)
            disassemble_range(value, value + 64);

        return;
    }

    const symbol_t *sym = lookup_symbol_entry(item);

    if (sym && sym->type == STT_FUNC) {
        unsigned long end_addr =
            sym->size ? sym->addr + sym->size : sym->addr + 64;

        disassemble_range(sym->addr, end_addr);
        return;
    }

    printf("unknown disassembly location: %s\n", item);
}

#define PTRACE_EVENT_EXEC 4

static int wait_for_exec(pid_t pid)
{
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC);

    for (int i = 0; i < 5; i++) {
        if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
            perror("ptrace cont");
            return -1;
        }

        int status;

        if (waitpid(pid, &status, 0) < 0) {
            perror("waitpid");
            return -1;
        }

        if (WIFEXITED(status))
            return -1;

        if (!WIFSTOPPED(status))
            continue;

        if (WSTOPSIG(status) == SIGTRAP &&
            ((status >> 16) & 0xffff) == PTRACE_EVENT_EXEC)
            return 0;
    }

    return -1;
}

void run_target(char *program)
{
    dbg.is_pie = 0;
    dbg.load_base = 0;

    pid_t pid = fork();

    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        execl(program, program, NULL);
        perror("execl");
        exit(1);
    }

    dbg.pid = pid;

    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
        printf("[-] process exited before exec\n");
        return;
    }

    strncpy(debuggee_path, program, sizeof(debuggee_path) - 1);
    debuggee_path[sizeof(debuggee_path) - 1] = '\0';

    if (!realpath(program, debuggee_realpath)) {
        strncpy(debuggee_realpath, program,
                sizeof(debuggee_realpath) - 1);
        debuggee_realpath[sizeof(debuggee_realpath) - 1] = '\0';
    }

    load_symbols(program);
    load_line_table(program);
    load_variables(program);

    if (wait_for_exec(pid) != 0) {
        printf("[-] failed to start target\n");
        dbg.running = 0;
        return;
    }

    if (update_load_base() != 0) {
        printf("[-] failed to read load base\n");
        dbg.running = 0;
        return;
    }

    dbg.running = 1;

    printf("[+] process started pid=%d\n", pid);
}

void show_regs()
{
    if (!dbg.running) {
        printf("no process\n");
        return;
    }

    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS,
           dbg.pid,
           0,
           &regs);

    printf("RIP : 0x%llx\n", regs.rip);
    show_pc_location(regs.rip);
    printf("RSP : 0x%llx\n", regs.rsp);
    printf("RAX : 0x%llx\n", regs.rax);
    printf("RBX : 0x%llx\n", regs.rbx);
    printf("RCX : 0x%llx\n", regs.rcx);
    printf("RDX : 0x%llx\n", regs.rdx);
}

long read_memory(unsigned long addr)
{
    errno = 0;

    long data =
        ptrace(
            PTRACE_PEEKDATA,
            dbg.pid,
            (void*)addr,
            0
        );

    if (errno != 0) {
        perror("ptrace peek");
        return -1;
    }

    return data;
}

static int peek_word(unsigned long addr, unsigned long *value)
{
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA,
                       dbg.pid,
                       (void *)addr,
                       0);

    if (errno != 0)
        return -1;

    *value = (unsigned long)data;
    return 0;
}

static void print_backtrace_frame(int frame, unsigned long addr)
{
    const symbol_t *sym = lookup_function_symbol(addr);
    unsigned long debug_addr = to_debug_addr(addr);
    const char *file;
    int line;

    printf("#%d  0x%lx", frame, addr);

    if (sym) {
        printf(" in %s", sym->name);
        if (debug_addr >= sym->addr)
            printf("+0x%lx", debug_addr - sym->addr);
    }

    if (lookup_line(addr, &file, &line) == 0)
        printf(" at %s:%d", file, line);

    printf("\n");
}

void show_backtrace(void)
{
    if (!dbg.running) {
        printf("no process\n");
        return;
    }

    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs) == -1) {
        perror("ptrace getregs");
        return;
    }

    unsigned long rbp = regs.rbp;
    unsigned long rip = regs.rip;

    print_backtrace_frame(0, rip);

    for (int frame = 1; frame < 32 && rbp != 0; frame++) {
        unsigned long next_rbp;
        unsigned long ret_addr;

        if (peek_word(rbp, &next_rbp) != 0 ||
            peek_word(rbp + 8, &ret_addr) != 0)
            break;

        if (ret_addr == 0)
            break;

        print_backtrace_frame(frame, ret_addr);

        if (next_rbp <= rbp)
            break;

        rbp = next_rbp;
    }
}

void examine_memory(unsigned long addr)
{
    if (!dbg.running) {
        printf("no process\n");
        return;
    }

    long data = read_memory(addr);

    printf("0x%lx : 0x%lx\n",
           addr,
           data);
}

void single_step()
{
    if (!dbg.running) {
        printf("no process\n");
        return;
    }

    ptrace(
        PTRACE_SINGLESTEP,
        dbg.pid,
        0,
        0
    );

    int status;

    waitpid(
        dbg.pid,
        &status,
        0
    );

    if (WIFEXITED(status)) {
        printf("[+] process exited\n");
        dbg.running = 0;
        return;
    }

    if (WIFSTOPPED(status)) {
        struct user_regs_struct regs;

        ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs);
        printf("[+] stepped\n");
        show_pc_location(regs.rip);
    }
}

void source_step()
{
    if (!dbg.running) {
        printf("no process\n");
        return;
    }

    struct user_regs_struct regs;
    const char *start_file;
    int start_line;

    ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs);

    if (lookup_line(regs.rip, &start_file, &start_line) != 0) {
        single_step();
        return;
    }

    for (int i = 0; i < 10000; i++) {
        if (ptrace(PTRACE_SINGLESTEP,
                   dbg.pid,
                   0,
                   0) == -1) {
            perror("ptrace singlestep");
            return;
        }

        int status;

        if (waitpid(dbg.pid, &status, 0) < 0) {
            perror("waitpid");
            return;
        }

        if (WIFEXITED(status)) {
            printf("[+] process exited\n");
            dbg.running = 0;
            return;
        }

        if (!WIFSTOPPED(status))
            continue;

        ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs);

        const char *file;
        int line;

        if (lookup_line(regs.rip, &file, &line) != 0) {
            printf("[+] stepped\n");
            show_pc_location(regs.rip);
            return;
        }

        if (line != start_line || strcmp(file, start_file)) {
            printf("[+] stepped\n");
            show_pc_location(regs.rip);
            return;
        }
    }

    printf("source step limit reached\n");
}

breakpoint_t* find_breakpoint(unsigned long addr)
{
    for (int i = 0; i < bp_count; i++) {

        if (breakpoints[i].addr == addr &&
            breakpoints[i].enabled) {

            return &breakpoints[i];
        }
    }

    return NULL;
}

void set_breakpoint(unsigned long addr)
{
    if (!dbg.running) {
        printf("no process\n");
        return;
    }

    addr = to_runtime_addr(addr);

    if (bp_count >= MAX_BREAKPOINTS) {
        printf("too many breakpoints\n");
        return;
    }

    if (find_breakpoint(addr)) {
        printf("breakpoint already exists\n");
        return;
    }

    /* read original instruction */
    long data =
        ptrace(
            PTRACE_PEEKDATA,
            dbg.pid,
            (void*)addr,
            0
        );

    if (data == -1) {
        perror("ptrace peek");
        return;
    }

    breakpoint_t *bp =
        &breakpoints[bp_count];

    bp->addr = addr;
    bp->original_data = data;
    bp->enabled = 1;

    /*
       replace first byte with INT3
       INT3 = 0xCC
    */

    long patched =
        (data & ~0xff) | 0xcc;

    if (ptrace(
            PTRACE_POKEDATA,
            dbg.pid,
            (void*)addr,
            (void*)patched) == -1) {

        perror("ptrace poke");
        return;
    }

    bp_count++;

    printf("[+] breakpoint set at 0x%lx\n",
           addr);
}

breakpoint_t* find_breakpoint_by_rip(unsigned long rip)
{
    /*
      INT3 executes
      RIP becomes bp+1
    */

    return find_breakpoint(rip - 1);
}

int restore_breakpoint(breakpoint_t *bp)
{
    if (ptrace(
            PTRACE_POKEDATA,
            dbg.pid,
            (void*)bp->addr,
            (void*)bp->original_data
        ) == -1) {
        perror("ptrace restore breakpoint");
        return -1;
    }

    return 0;
}

int enable_breakpoint(breakpoint_t *bp)
{
    long patched =
        (bp->original_data & ~0xff) | 0xcc;

    if (ptrace(
            PTRACE_POKEDATA,
            dbg.pid,
            (void*)bp->addr,
            (void*)patched
        ) == -1) {
        perror("ptrace enable breakpoint");
        return -1;
    }

    return 0;
}

void rewind_rip(unsigned long addr)
{
    struct user_regs_struct regs;

    ptrace(
        PTRACE_GETREGS,
        dbg.pid,
        0,
        &regs
    );

    regs.rip = addr;

    ptrace(
        PTRACE_SETREGS,
        dbg.pid,
        0,
        &regs
    );
}

int step_over_breakpoint(breakpoint_t *bp)
{
    /*
      restore original instruction
    */

    if (restore_breakpoint(bp) != 0)
        return -1;

    /*
      RIP = original address
    */

    rewind_rip(bp->addr);

    /*
      execute 1 instruction
    */

    if (ptrace(
            PTRACE_SINGLESTEP,
            dbg.pid,
            0,
            0
        ) == -1) {
        perror("ptrace singlestep");
        return -1;
    }

    int status;

    if (waitpid(
            dbg.pid,
            &status,
            0
        ) < 0) {
        perror("waitpid");
        return -1;
    }

    if (WIFEXITED(status)) {
        printf("[+] process exited\n");
        dbg.running = 0;
        return -1;
    }

    /*
      put INT3 back
    */

    if (enable_breakpoint(bp) != 0)
        return -1;

    return 0;
}

static int arm_temp_breakpoint(finish_bp_t *tp, unsigned long addr)
{
    breakpoint_t *existing = find_breakpoint(addr);

    tp->active = 1;
    tp->addr = addr;

    if (existing) {
        tp->uses_existing = 1;
        tp->original_data = 0;
        return 0;
    }

    long data = read_memory(addr);

    if (data == -1) {
        tp->active = 0;
        return -1;
    }

    tp->uses_existing = 0;
    tp->original_data = data;

    long patched = (data & ~0xff) | 0xcc;

    if (ptrace(PTRACE_POKEDATA,
               dbg.pid,
               (void *)addr,
               (void *)patched) == -1) {
        perror("ptrace poke");
        tp->active = 0;
        return -1;
    }

    return 0;
}

static void disarm_temp_breakpoint(finish_bp_t *tp)
{
    if (!tp->active)
        return;

    if (!tp->uses_existing) {
        ptrace(
            PTRACE_POKEDATA,
            dbg.pid,
            (void *)tp->addr,
            (void *)tp->original_data
        );
    }

    tp->active = 0;
}

static unsigned long handle_temp_stop(finish_bp_t *tp)
{
    if (!tp->uses_existing) {
        ptrace(
            PTRACE_POKEDATA,
            dbg.pid,
            (void *)tp->addr,
            (void *)tp->original_data
        );
    }

    unsigned long addr = tp->addr;

    rewind_rip(addr);
    tp->active = 0;

    return addr;
}

void handle_finish_hit(void)
{
    unsigned long addr = handle_temp_stop(&finish_bp);

    printf("[+] returned to 0x%lx\n", addr);
    show_pc_location(addr);
}

void handle_next_hit(void)
{
    unsigned long addr = handle_temp_stop(&next_bp);

    printf("[+] next line at 0x%lx\n", addr);
    show_pc_location(addr);
}

int get_return_address(unsigned long *ret_addr)
{
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs);

    unsigned long debug_rip = to_debug_addr(regs.rip);
    unsigned long func_start = 0;

    for (int i = 0; i < sym_count; i++) {
        if (symbols[i].type == STT_FUNC &&
            symbols[i].addr <= debug_rip &&
            symbols[i].addr >= func_start) {
            func_start = symbols[i].addr;
        }
    }

    unsigned long candidates[2];
    int count = 0;

    long from_rsp = read_memory(regs.rsp);

    if (from_rsp != -1)
        candidates[count++] = (unsigned long)from_rsp;

    if (regs.rbp != 0) {
        long from_rbp = read_memory(regs.rbp + 8);

        if (from_rbp != -1)
            candidates[count++] = (unsigned long)from_rbp;
    }

    for (int i = 0; i < count; i++) {
        unsigned long addr = candidates[i];
        unsigned long debug_addr = to_debug_addr(addr);

        if (line_entry_count > 0 &&
            (debug_addr < line_addr_min ||
             debug_addr > line_addr_max))
            continue;

        if (debug_addr > func_start && debug_addr != debug_rip) {
            *ret_addr = addr;
            return 0;
        }
    }

    return -1;
}

void continue_execution(void);

void finish_function(void)
{
    if (!dbg.running) {
        printf("no process\n");
        return;
    }

    if (finish_bp.active) {
        printf("already finishing\n");
        return;
    }

    if (next_bp.active) {
        printf("already stepping to next line\n");
        return;
    }

    unsigned long ret_addr;

    if (get_return_address(&ret_addr) != 0) {
        printf("cannot find return address\n");
        return;
    }

    if (arm_temp_breakpoint(&finish_bp, ret_addr) != 0)
        return;

    printf("[+] finish until 0x%lx\n", ret_addr);
    continue_execution();
}

void next_line(void)
{
    if (!dbg.running) {
        printf("no process\n");
        return;
    }

    if (finish_bp.active) {
        printf("already finishing\n");
        return;
    }

    if (next_bp.active) {
        printf("already stepping to next line\n");
        return;
    }

    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs);

    const char *file;
    int line;

    if (lookup_line(regs.rip, &file, &line) != 0) {
        printf("no line info\n");
        return;
    }

    int next_line_num;
    unsigned long next_addr;

    if (lookup_next_line_scoped(regs.rip, file, line,
                              &next_line_num, &next_addr) != 0) {
        printf("no next line\n");
        return;
    }

    if (arm_temp_breakpoint(&next_bp, next_addr) != 0)
        return;

    printf("[+] next until %s:%d (0x%lx)\n",
           file_basename(file), next_line_num, next_addr);
    continue_execution();
}

void continue_execution()
{
    if (!dbg.running) {
        printf("no process\n");
        return;
    }

    ptrace(
        PTRACE_CONT,
        dbg.pid,
        0,
        0
    );

    int status;

    waitpid(
        dbg.pid,
        &status,
        0
    );

    if (WIFEXITED(status)) {
        disarm_temp_breakpoint(&next_bp);
        disarm_temp_breakpoint(&finish_bp);
        printf("[+] process exited\n");
        dbg.running = 0;
        return;
    }

    if (WIFSTOPPED(status)) {

        int sig = WSTOPSIG(status);

        if (sig == SIGTRAP) {

            struct user_regs_struct regs;

            ptrace(
                PTRACE_GETREGS,
                dbg.pid,
                0,
                &regs
            );

            if (next_bp.active &&
                regs.rip - 1 == next_bp.addr) {
                handle_next_hit();
                return;
            }

            if (finish_bp.active &&
                regs.rip - 1 == finish_bp.addr) {
                handle_finish_hit();
                return;
            }

            breakpoint_t *bp =
                find_breakpoint_by_rip(
                    regs.rip
                );

            if (bp) {
                disarm_temp_breakpoint(&next_bp);
                disarm_temp_breakpoint(&finish_bp);

                printf(
                    "[+] breakpoint hit 0x%lx\n",
                    bp->addr
                );
                show_stop_location(bp->addr);

                if (step_over_breakpoint(bp) != 0)
                    printf("[-] failed to re-enable breakpoint\n");

                return;
            }
        }

        struct user_regs_struct regs;

        ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs);

        printf(
            "[+] stopped signal=%d\n",
            sig
        );
        show_stop_location(regs.rip);
    }
}

void handle(char *line)
{
    if (!strncmp(line, "run ", 4)) {

        char program[256];

        sscanf(line, "run %255s", program);

        run_target(program);
    }

    else if (!strcmp(line, "c\n")) {
        continue_execution();
    }

    else if (!strcmp(line, "s\n")) {
        source_step();
    }

    else if (!strcmp(line, "si\n")) {
        single_step();
    }

    else if (!strcmp(line, "n\n")) {
        next_line();
    }

    else if (!strcmp(line, "up\n")) {
        finish_function();
    }

    else if (!strcmp(line, "regs\n")) {
        show_regs();
    }

    else if (!strcmp(line, "syms\n")) {
        show_symbols();
    }

    else if (!strcmp(line, "tb\n")) {
        show_backtrace();
    }

    else if (!strncmp(line, "l ", 2) ||
             !strcmp(line, "l\n") ||
             !strncmp(line, "list ", 5) ||
             !strcmp(line, "list\n")) {
        char *arg_start =
            !strncmp(line, "list", 4) ? line + 4 : line + 1;

        list_source(arg_start);
    }

    else if (!strncmp(line, "dis ", 4)) {
        disassemble_command(line + 4);
    }

    else if (!strncmp(line, "p ", 2) ||
             !strcmp(line, "p\n")) {
        print_expression(line + 2);
    }

    else if (!strncmp(line, "print ", 6) ||
             !strcmp(line, "print\n")) {
        print_expression(line + 6);
    }

    else if (!strncmp(line, "set ", 4)) {
        set_command(line + 4);
    }

    else if (!strncmp(line, "show ", 5) ||
             !strcmp(line, "show\n")) {
        show_command(line + 5);
    }

    else if (!strncmp(line, "x ", 2)) {

        unsigned long addr;

        sscanf(line, "x %lx", &addr);

        examine_memory(addr);
    }

    else if (!strcmp(line, "q\n")) {
        exit(0);
    }

    else if (!strncmp(line, "b ", 2) ||
             !strncmp(line, "break ", 6)) {

        char arg[256];
        char *arg_start =
            !strncmp(line, "b ", 2) ? line + 2 : line + 6;

        if (sscanf(arg_start, "%255s", arg) != 1) {
            printf("usage: b|break <addr|symbol|file:line>\n");
            return;
        }

        unsigned long addr;
        char *colon = strrchr(arg, ':');

        if (colon && colon[1] != '\0') {
            char file[256];
            size_t file_len = colon - arg;

            if (file_len >= sizeof(file)) {
                printf("invalid location: %s\n", arg);
                return;
            }

            memcpy(file, arg, file_len);
            file[file_len] = '\0';

            char *line_end;
            long line_num = strtol(colon + 1, &line_end, 10);

            if (*line_end == '\0' && line_num > 0) {
                if (lookup_line_addr(file, (int)line_num, &addr) == 0) {
                    set_breakpoint(addr);
                } else {
                    printf("no line info for %s:%ld\n",
                           file, line_num);
                }
                return;
            }
        }

        char *end;

        addr = strtoul(arg, &end, 0);

        if (*end == '\0' && end != arg) {
            set_breakpoint(addr);
        } else {
            const symbol_t *sym = lookup_symbol_entry(arg);

            if (!sym) {
                printf("unknown symbol: %s\n", arg);
                return;
            }

            addr = sym->addr;

            if (sym->type == STT_FUNC)
                lookup_function_body_addr(sym, &addr);

            set_breakpoint(addr);
        }
    }

    else {
        printf("unknown command\n");
    }
}
void repl()
{
    char line[256];

    while (1) {

        printf("(mini-gdb) ");

        if (!fgets(line,
                   sizeof(line),
                   stdin))
            break;

        handle(line);
    }
}

int main()
{
    repl();
    return 0;
}