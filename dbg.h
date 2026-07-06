#ifndef DBG_H
#define DBG_H

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

extern debugger_t dbg;
extern char debuggee_path[512];
extern char debuggee_realpath[512];

#define MAX_BREAKPOINTS 32

typedef struct {
    unsigned long addr;
    long original_data;
    int enabled;
} breakpoint_t;

extern breakpoint_t breakpoints[MAX_BREAKPOINTS];
extern int bp_count;

typedef struct {
    int active;
    int uses_existing;
    unsigned long addr;
    long original_data;
} finish_bp_t;

extern finish_bp_t finish_bp;
extern finish_bp_t next_bp;

#define MAX_SYMBOLS 1024

typedef struct {
    char name[256];
    unsigned long addr;
    unsigned long size;
    unsigned char type;
} symbol_t;

extern symbol_t symbols[MAX_SYMBOLS];
extern int sym_count;

#define MAX_LINE_ENTRIES 4096

typedef struct {
    unsigned long addr;
    char file[512];
    int line;
} line_entry_t;

extern line_entry_t line_entries[MAX_LINE_ENTRIES];
extern int line_entry_count;
extern unsigned long line_addr_min;
extern unsigned long line_addr_max;

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

extern var_entry_t vars[MAX_VARS];
extern int var_count;

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

extern int dwarf_addr_size;

uint64_t read_uleb128(const uint8_t *data, size_t len, size_t *off);
int64_t read_sleb128(const uint8_t *data, size_t len, size_t *off);
unsigned long to_debug_addr(unsigned long addr);
unsigned long to_runtime_addr(unsigned long addr);
void trim_line(char *s);
int parse_on_off(const char *name, int *value);
const char *file_basename(const char *path);
int file_matches(const char *entry_file, const char *query);

long read_memory(unsigned long addr);
int peek_word(unsigned long addr, unsigned long *value);
int poke_word(unsigned long addr, unsigned long value);
void examine_memory(unsigned long addr);
int read_target_byte(unsigned long addr, unsigned char *out);

void load_variables(char *path);
void load_line_table(char *path);
int lookup_line(unsigned long addr, const char **file, int *line);
int lookup_line_addr(const char *file, int line, unsigned long *addr);
int lookup_next_line(const char *file, int line, int *next_line,
                     unsigned long *addr);
int lookup_next_line_scoped(unsigned long rip, const char *file, int line,
                            int *next_line, unsigned long *addr);
var_entry_t *lookup_var(const char *name, unsigned long rip);
int get_cached_type(uint32_t off, type_info_t *out);
void resolve_type_alias(type_info_t *ti, uint32_t *orig_off);

void set_command(const char *args);
void show_command(const char *args);
void print_expression(const char *expr);

void load_symbols(char *path);
void show_symbols(void);
int lookup_symbol(const char *name, unsigned long *addr);
const symbol_t *lookup_symbol_entry(const char *name);
int lookup_function_body_addr(const symbol_t *sym, unsigned long *addr);
const symbol_t *lookup_function_symbol(unsigned long addr);
int update_load_base(void);

void run_target(char *program);
void show_regs(void);
void show_backtrace(void);
void single_step(void);
void source_step(void);
void set_breakpoint(unsigned long addr);
breakpoint_t *find_breakpoint(unsigned long addr);
breakpoint_t *find_breakpoint_by_rip(unsigned long rip);
int restore_breakpoint(breakpoint_t *bp);
int enable_breakpoint(breakpoint_t *bp);
void rewind_rip(unsigned long addr);
int step_over_breakpoint(breakpoint_t *bp);
void handle_finish_hit(void);
void handle_next_hit(void);
int get_return_address(unsigned long *ret_addr);
void finish_function(void);
void next_line(void);
void continue_execution(void);

int show_source_listing(const char *file, int line);
void show_stop_location(unsigned long pc);
void list_source(const char *arg);
void show_pc_location(unsigned long rip);
void disassemble_command(const char *arg);

void handle(char *line);
void repl(void);

#endif
