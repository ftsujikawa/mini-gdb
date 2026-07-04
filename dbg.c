#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
} debugger_t;

debugger_t dbg = {0};
char debuggee_path[512];

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
} var_entry_t;

var_entry_t vars[MAX_VARS];
int var_count = 0;

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
int lookup_symbol(const char *name, unsigned long *addr);

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
                          size_t loc_len)
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
    var_count++;
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
            add_var_entry(name, scope_low, scope_high, loc, loc_len);
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

        parse_dies(&off, unit_end, 0, ~0UL);
        off = unit_end;
    }

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

void print_variable(const char *name)
{
    if (!dbg.running) {
        printf("no process\n");
        return;
    }

    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs);

    var_entry_t *v = lookup_var(name, regs.rip);

    if (v) {
        unsigned long addr;

        if (v->loc == VAR_FBREG)
            addr = regs.rbp + 16 + v->fbreg;
        else
            addr = v->addr;

        long word = read_memory(addr);

        if (word == -1)
            return;

        printf("%s = %d\n", name, (int)word);
        return;
    }

    for (int i = 0; i < sym_count; i++) {
        if (symbols[i].type != STT_OBJECT)
            continue;

        if (!strcmp(symbols[i].name, name)) {
            long word = read_memory(symbols[i].addr);

            if (word == -1)
                return;

            printf("%s = %ld\n", name, word);
            return;
        }
    }

    printf("unknown variable: %s\n", name);
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
    unsigned long func_end = current_func_end(rip);
    unsigned long best = 0;
    int best_line = 0;

    for (int i = 0; i < line_entry_count; i++) {
        if (line_entries[i].addr <= rip)
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
        *addr = best;
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

void show_source_listing(const char *file, int line)
{
    FILE *fp = fopen(file, "r");

    if (!fp) {
        printf("(cannot open %s)\n", file);
        return;
    }

    char buf[1024];
    int cur = 0;
    int start = line - SOURCE_CONTEXT;

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
            printf("=> %4d  %s\n", cur, buf);
        else
            printf("   %4d  %s\n", cur, buf);
    }

    fclose(fp);
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

void show_pc_location(unsigned long rip)
{
    const char *file;
    int line;

    if (lookup_line(rip, &file, &line) == 0) {
        printf("=> %s:%d\n", file, line);
        show_source_listing(file, line);
    }
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

    load_symbols(program);
    load_line_table(program);
    load_variables(program);

    if (wait_for_exec(pid) != 0) {
        printf("[-] failed to start target\n");
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
    const char *file;
    int line;

    printf("#%d  0x%lx", frame, addr);

    if (sym) {
        printf(" in %s", sym->name);
        if (addr >= sym->addr)
            printf("+0x%lx", addr - sym->addr);
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

void restore_breakpoint(breakpoint_t *bp)
{
    ptrace(
        PTRACE_POKEDATA,
        dbg.pid,
        (void*)bp->addr,
        (void*)bp->original_data
    );
}

void enable_breakpoint(breakpoint_t *bp)
{
    long patched =
        (bp->original_data & ~0xff) | 0xcc;

    ptrace(
        PTRACE_POKEDATA,
        dbg.pid,
        (void*)bp->addr,
        (void*)patched
    );
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

void step_over_breakpoint(breakpoint_t *bp)
{
    /*
      restore original instruction
    */

    restore_breakpoint(bp);

    /*
      RIP = original address
    */

    rewind_rip(bp->addr);

    /*
      execute 1 instruction
    */

    ptrace(
        PTRACE_SINGLESTEP,
        dbg.pid,
        0,
        0
    );

    waitpid(
        dbg.pid,
        NULL,
        0
    );

    /*
      put INT3 back
    */

    enable_breakpoint(bp);
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

    unsigned long func_start = 0;

    for (int i = 0; i < sym_count; i++) {
        if (symbols[i].type == STT_FUNC &&
            symbols[i].addr <= regs.rip &&
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

        if (line_entry_count > 0 &&
            (addr < line_addr_min || addr > line_addr_max))
            continue;

        if (addr > func_start && addr != regs.rip) {
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
                show_pc_location(bp->addr);

                step_over_breakpoint(bp);

                return;
            }
        }

        struct user_regs_struct regs;

        ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs);

        printf(
            "[+] stopped signal=%d\n",
            sig
        );
        show_pc_location(regs.rip);
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

    else if (!strncmp(line, "p ", 2)) {

        char name[256];

        if (sscanf(line + 2, "%255s", name) == 1)
            print_variable(name);
    }

    else if (!strncmp(line, "print ", 6)) {

        char name[256];

        if (sscanf(line + 6, "%255s", name) == 1)
            print_variable(name);
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