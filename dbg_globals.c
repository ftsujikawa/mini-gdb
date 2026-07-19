#include "dbg.h"

debugger_t dbg = {0};
char debuggee_path[512];
char debuggee_realpath[512];
breakpoint_t breakpoints[MAX_BREAKPOINTS];
watchpoint_t watchpoints[MAX_WATCHPOINTS];
thread_t threads[MAX_THREADS];

int bp_count = 0;
int wp_count = 0;
int thread_count = 0;
finish_bp_t finish_bp = {0};
finish_bp_t next_bp = {0};
symbol_t symbols[MAX_SYMBOLS];
int sym_count = 0;
line_entry_t line_entries[MAX_LINE_ENTRIES];
int line_entry_count = 0;
unsigned long line_addr_min = 0;
unsigned long line_addr_max = 0;
var_entry_t vars[MAX_VARS];
int var_count = 0;
