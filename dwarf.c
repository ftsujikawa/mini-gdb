#include "dbg.h"

typedef struct {
    uint64_t code;
    uint64_t tag;
    int has_children;
    uint8_t attr[32];
    uint8_t form[32];
    int64_t implicit[32];
    int nattr;
} dwarf_abbrev_t;

static type_cache_entry_t type_cache[MAX_TYPE_CACHE];
static int type_cache_count = 0;
static size_t current_cu_base = 0;

static int get_type_info(uint32_t off, type_info_t *out);

static dwarf_abbrev_t abbrevs[MAX_ABBREVS];
static int abbrev_count = 0;
static const uint8_t *debug_info;
static size_t debug_info_size;
static const uint8_t *debug_str;
static size_t debug_str_size;
int dwarf_addr_size = 8;
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
                          uint32_t type_off,
                          uint64_t tag)
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

    if (tag == DW_TAG_formal_parameter)
        v->kind = VAR_KIND_ARG;
    else if (v->loc == VAR_ADDR)
        v->kind = VAR_KIND_GLOBAL;
    else
        v->kind = VAR_KIND_LOCAL;

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

int get_cached_type(uint32_t off, type_info_t *out)
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

void resolve_type_alias(type_info_t *ti, uint32_t *orig_off)
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
                          type_off, ab->tag);
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
var_entry_t *lookup_var(const char *name, unsigned long rip)
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

static unsigned long dbg_current_rip(void)
{
    if (!dbg.running)
        return 0;

    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs) == -1)
        return 0;

    return regs.rip;
}

static const char *type_kind_name(type_kind_t kind)
{
    switch (kind) {
    case TYPE_BASE:    return "base";
    case TYPE_POINTER: return "pointer";
    case TYPE_STRUCT:  return "struct";
    case TYPE_ARRAY:   return "array";
    case TYPE_ALIAS:   return "alias";
    default:           return "unknown";
    }
}

static void print_type_info(uint32_t type_off, int depth)
{
    type_info_t ti;
    uint32_t orig = type_off;
    char indent[32];

    if (depth >= (int)sizeof(indent))
        depth = (int)sizeof(indent) - 1;

    memset(indent, ' ', depth * 2);
    indent[depth * 2] = '\0';

    if (type_off == 0 || get_cached_type(type_off, &ti) != 0) {
        printf("%stype: (unknown)\n", indent);
        return;
    }

    resolve_type_alias(&ti, &orig);

    printf("%stype: %s", indent, type_kind_name(ti.kind));

    if (ti.struct_name[0])
        printf(" '%s'", ti.struct_name);

    printf(" (size=%zu", ti.size);

    if (ti.kind == TYPE_BASE) {
        if (ti.encoding == DW_ATE_signed)
            printf(", signed");
        else if (ti.encoding == DW_ATE_unsigned)
            printf(", unsigned");
    }

    if (ti.kind == TYPE_ARRAY && ti.array_count > 0)
        printf(", count=%d", ti.array_count);

    printf(", die=0x%x", orig);
    printf(")\n");

    if (ti.kind == TYPE_POINTER && ti.ref_off)
        print_type_info(ti.ref_off, depth + 1);

    if (ti.kind == TYPE_ARRAY && ti.elem_type_off)
        print_type_info(ti.elem_type_off, depth + 1);

    if (ti.kind == TYPE_STRUCT) {
        for (int i = 0; i < ti.member_count; i++) {
            printf("%s  %s @+%ld\n",
                   indent,
                   ti.members[i].name,
                   ti.members[i].offset);

            if (ti.members[i].type_off)
                print_type_info(ti.members[i].type_off, depth + 1);
        }
    }
}

static void show_var_detail(const var_entry_t *v)
{
    unsigned long lo = v->scope_low;
    unsigned long hi = v->scope_high;

    if (dbg.running) {
        lo = to_runtime_addr(lo);
        hi = to_runtime_addr(hi);
    }

    printf("Variable: %s\n", v->name);
    printf("Scope:    0x%lx - 0x%lx", lo, hi);

    const symbol_t *sym = lookup_function_symbol(lo);

    if (sym)
        printf(" (%s)", sym->name);

    putchar('\n');

    if (v->loc == VAR_FBREG)
        printf("Location: fbreg %ld (rbp%+ld)\n", v->fbreg, v->fbreg);
    else {
        unsigned long addr = v->addr;

        if (dbg.running)
            addr = to_runtime_addr(addr);

        printf("Location: addr 0x%lx\n", addr);
    }

    print_type_info(v->type_off, 1);
}

static void show_all_vars(void)
{
    if (var_count == 0) {
        printf("no debug variables loaded (use run first)\n");
        return;
    }

    printf("Num  Name                 Scope                         Location\n");

    for (int i = 0; i < var_count; i++) {
        const var_entry_t *v = &vars[i];
        unsigned long lo = v->scope_low;
        unsigned long hi = v->scope_high;

        if (dbg.running) {
            lo = to_runtime_addr(lo);
            hi = to_runtime_addr(hi);
        }

        printf("%-4d %-20s 0x%lx-0x%lx ", i + 1, v->name, lo, hi);

        if (v->loc == VAR_FBREG)
            printf("fbreg %ld", v->fbreg);
        else {
            unsigned long addr = v->addr;

            if (dbg.running)
                addr = to_runtime_addr(addr);

            printf("addr 0x%lx", addr);
        }

        putchar('\n');
    }

    printf("%d variable(s)\n", var_count);
}

static void show_line_table(const char *file_filter)
{
    if (line_entry_count == 0) {
        printf("no line info loaded (use run first)\n");
        return;
    }

    int shown = 0;

    printf("Address            Line  File\n");

    for (int i = 0; i < line_entry_count; i++) {
        if (file_filter && file_filter[0] &&
            !file_matches(line_entries[i].file, file_filter))
            continue;

        unsigned long addr = line_entries[i].addr;

        if (dbg.running)
            addr = to_runtime_addr(addr);

        printf("0x%-16lx %-5d %s\n",
               addr,
               line_entries[i].line,
               line_entries[i].file);
        shown++;
    }

    if (shown == 0)
        printf("no matching line entries\n");
    else
        printf("%d line entr%s\n", shown, shown == 1 ? "y" : "ies");
}

static void show_location_info(unsigned long addr)
{
    const char *file;
    int line;
    const symbol_t *sym = lookup_function_symbol(addr);
    unsigned long debug_addr = to_debug_addr(addr);

    printf("Address: 0x%lx\n", addr);

    if (sym) {
        printf("Symbol:  %s", sym->name);

        if (debug_addr >= sym->addr)
            printf("+0x%lx", debug_addr - sym->addr);

        putchar('\n');
    }

    if (lookup_line(addr, &file, &line) == 0)
        printf("Line:    %s:%d\n", file, line);

    int in_scope = 0;

    for (int i = 0; i < var_count; i++) {
        if (debug_addr >= vars[i].scope_low &&
            debug_addr < vars[i].scope_high) {
            if (!in_scope) {
                printf("Variables in scope:\n");
                in_scope = 1;
            }

            printf("  %s\n", vars[i].name);
        }
    }

    if (!in_scope)
        printf("Variables in scope: (none)\n");
}

static void dbg_show_var(const char *name)
{
    if (var_count == 0) {
        printf("no debug variables loaded (use run first)\n");
        return;
    }

    unsigned long rip = dbg_current_rip();
    var_entry_t *v = NULL;

    if (rip != 0)
        v = lookup_var(name, rip);

    if (!v) {
        for (int i = 0; i < var_count; i++) {
            if (!strcmp(vars[i].name, name)) {
                v = &vars[i];
                break;
            }
        }
    }

    if (!v) {
        printf("no debug info for variable: %s\n", name);
        return;
    }

    if (rip != 0 &&
        (to_debug_addr(rip) < v->scope_low ||
         to_debug_addr(rip) >= v->scope_high))
        printf("note: not in scope at current pc\n");

    show_var_detail(v);
}

static void dbg_show_line(const char *loc)
{
    char item[256];
    unsigned long addr;
    char *colon;
    char *end;

    strncpy(item, loc, sizeof(item) - 1);
    item[sizeof(item) - 1] = '\0';

    colon = strrchr(item, ':');

    if (colon && colon[1] != '\0') {
        char file[256];
        size_t file_len = colon - item;
        long line_num;

        if (file_len >= sizeof(file)) {
            printf("invalid location: %s\n", loc);
            return;
        }

        memcpy(file, item, file_len);
        file[file_len] = '\0';

        line_num = strtol(colon + 1, &end, 10);

        if (*end == '\0' && line_num > 0) {
            if (lookup_line_addr(file, (int)line_num, &addr) != 0) {
                printf("no line info for %s\n", loc);
                return;
            }

            if (dbg.running)
                addr = to_runtime_addr(addr);

            show_location_info(addr);
            return;
        }
    }

    addr = strtoul(item, &end, 0);

    if (*end == '\0' && end != item) {
        if (dbg.running)
            addr = to_runtime_addr(to_debug_addr(addr));

        show_location_info(addr);
        return;
    }

    const symbol_t *sym = lookup_symbol_entry(item);

    if (!sym) {
        printf("no debug info for: %s\n", loc);
        return;
    }

    addr = sym->addr;

    if (sym->type == STT_FUNC)
        lookup_function_body_addr(sym, &addr);

    if (dbg.running)
        addr = to_runtime_addr(addr);

    show_location_info(addr);
}

static void dbg_show_usage(void)
{
    printf("usage:\n");
    printf("  dbg vars                 list all debug variables\n");
    printf("  dbg var <name>           show variable debug info\n");
    printf("  dbg lines [file]         list line number table\n");
    printf("  dbg line <loc>           show debug info for location\n");
    printf("                           (addr, symbol, or file:line)\n");
}

void dbg_command(const char *args)
{
    char buf[256];

    strncpy(buf, args, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    trim_line(buf);
    args = buf;

    while (*args == ' ' || *args == '\t')
        args++;

    if (*args == '\0') {
        dbg_show_usage();
        return;
    }

    if (!strcmp(args, "vars")) {
        show_all_vars();
        return;
    }

    if (!strncmp(args, "var ", 4)) {
        args += 4;

        while (*args == ' ')
            args++;

        if (*args == '\0') {
            printf("usage: dbg var <name>\n");
            return;
        }

        dbg_show_var(args);
        return;
    }

    if (!strcmp(args, "lines")) {
        show_line_table(NULL);
        return;
    }

    if (!strncmp(args, "lines ", 6)) {
        show_line_table(args + 6);
        return;
    }

    if (!strncmp(args, "line ", 5)) {
        args += 5;

        while (*args == ' ')
            args++;

        if (*args == '\0') {
            printf("usage: dbg line <addr|symbol|file:line>\n");
            return;
        }

        dbg_show_line(args);
        return;
    }

    dbg_show_usage();
}
