#include "dbg.h"
#include "heap.h"

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
    wp_count = 0; /* hardware watchpoints don't survive across processes */

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

    heap_reset();
    if (heap_trace_enabled())
        heap_arm_hooks();

    printf("[+] process started pid=%d\n", pid);
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

void show_breakpoints(void)
{
    if (bp_count == 0) {
        printf("no breakpoints\n");
        return;
    }

    printf("Num  Enb  Address            What\n");

    for (int i = 0; i < bp_count; i++) {
        breakpoint_t *bp = &breakpoints[i];
        const char *file;
        int line;

        printf("%-4d %-4s 0x%-16lx",
               i + 1,
               bp->enabled ? "y" : "n",
               bp->addr);

        const symbol_t *sym = lookup_function_symbol(bp->addr);

        if (sym) {
            unsigned long debug_addr = to_debug_addr(bp->addr);

            printf(" %s", sym->name);

            if (debug_addr > sym->addr)
                printf("+0x%lx", debug_addr - sym->addr);
        }

        if (lookup_line(bp->addr, &file, &line) == 0) {
            if (sym)
                printf(" at ");
            else
                printf(" ");

            printf("%s:%d", file, line);
        }

        putchar('\n');
    }
}

breakpoint_t* find_breakpoint_by_rip(unsigned long rip)
{
    /*
      INT3 executes
      RIP becomes bp+1
    */

    return find_breakpoint(rip - 1);
}

int delete_breakpoint(int num)
{
    if (num < 1 || num > bp_count) {
        printf("invalid breakpoint number: %d\n", num);
        return -1;
    }

    breakpoint_t *bp = &breakpoints[num - 1];

    if (bp->enabled) {
        if (restore_breakpoint(bp) == -1)
            return -1;
    }

    /* Shift remaining breakpoints down */
    for (int i = num - 1; i < bp_count - 1; i++)
        breakpoints[i] = breakpoints[i + 1];

    bp_count--;
    printf("Breakpoint %d deleted\n", num);
    return 0;
}

static long peek_debugreg(int i)
{
    return ptrace(PTRACE_PEEKUSER, dbg.pid,
                  (void *)(offsetof(struct user, u_debugreg[0]) +
                           (size_t)i * sizeof(unsigned long long)),
                  0);
}

static int poke_debugreg(int i, unsigned long val)
{
    return ptrace(PTRACE_POKEUSER, dbg.pid,
                  (void *)(offsetof(struct user, u_debugreg[0]) +
                           (size_t)i * sizeof(unsigned long long)),
                  (void *)val);
}

static long mask_for_size(int size, long value)
{
    if (size >= 8)
        return value;

    return value & ((1L << (size * 8)) - 1);
}

static int dr7_len_bits(int size)
{
    switch (size) {
    case 1: return 0x0;
    case 2: return 0x1;
    case 8: return 0x2;
    default: return 0x3; /* 4 bytes */
    }
}

static int arm_watch_slot(int slot, unsigned long addr, int size,
                           int access_mode)
{
    if (poke_debugreg(slot, addr) == -1) {
        perror("ptrace poke debugreg");
        return -1;
    }

    long dr7 = peek_debugreg(7);

    if (dr7 == -1)
        dr7 = 0;

    /* R/W field: 0b01 = break on writes only, 0b11 = break on any
     * read or write access. x86 has no pure read-only mode, so /r
     * (access_mode) uses 0b11 like gdb's `awatch`. */
    long rw = access_mode ? 0x3L : 0x1L;

    dr7 &= ~(0x3L << (slot * 2));       /* clear L/G enable */
    dr7 &= ~(0x3L << (16 + slot * 4));  /* clear R/W field */
    dr7 &= ~(0x3L << (18 + slot * 4));  /* clear LEN field */

    dr7 |= (0x1L << (slot * 2));        /* local enable */
    dr7 |= (rw << (16 + slot * 4));
    dr7 |= ((long)dr7_len_bits(size) << (18 + slot * 4));

    if (poke_debugreg(7, (unsigned long)dr7) == -1) {
        perror("ptrace poke debugreg");
        return -1;
    }

    return 0;
}

static void disarm_watch_slot(int slot)
{
    long dr7 = peek_debugreg(7);

    if (dr7 == -1)
        return;

    dr7 &= ~(0x3L << (slot * 2));
    poke_debugreg(7, (unsigned long)dr7);
}

/* Parses leading "/r" and "/1"|"/2"|"/4"|"/8" flag tokens (in either
 * order, combined like "/r4" or separate like "/r /4") off the front of
 * a `watch` argument string. Returns a pointer to the remaining
 * expression text, or NULL (after printing a usage message) if an
 * unrecognized flag character was found. */
static const char *parse_watch_flags(const char *args, int *access_mode,
                                      int *size_override)
{
    *access_mode = 0;
    *size_override = 0;

    while (*args == ' ' || *args == '\t')
        args++;

    while (*args == '/') {
        args++;

        while (*args && *args != ' ' && *args != '\t') {
            switch (*args) {
            case 'r':
            case 'R':
                *access_mode = 1;
                break;
            case '1':
                *size_override = 1;
                break;
            case '2':
                *size_override = 2;
                break;
            case '4':
                *size_override = 4;
                break;
            case '8':
                *size_override = 8;
                break;
            default:
                printf("usage: watch [/r] [/1|/2|/4|/8] <expr>\n");
                return NULL;
            }
            args++;
        }

        while (*args == ' ' || *args == '\t')
            args++;
    }

    return args;
}

void watch_command(const char *args)
{
    if (!dbg.running) {
        printf("no process\n");
        return;
    }

    if (wp_count >= MAX_WATCHPOINTS) {
        printf("too many watchpoints (max %d, hardware-limited)\n",
               MAX_WATCHPOINTS);
        return;
    }

    int access_mode;
    int size_override;
    const char *expr = parse_watch_flags(args, &access_mode, &size_override);

    if (!expr)
        return;

    if (!*expr) {
        printf("usage: watch [/r] [/1|/2|/4|/8] <expr>\n");
        return;
    }

    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs);

    unsigned long addr;
    uint32_t type_off;
    char label[128];

    if (resolve_lvalue(expr, regs.rip, &addr, &type_off,
                        label, sizeof(label)) != 0) {
        printf("cannot resolve: %s\n", expr);
        return;
    }

    int size = size_override;

    if (size == 0) {
        type_info_t ti = {
            .kind = TYPE_BASE,
            .size = 4,
            .encoding = DW_ATE_signed,
        };

        if (type_off != 0)
            get_cached_type(type_off, &ti);

        size = (int)ti.size;

        if (size != 1 && size != 2 && size != 4 && size != 8) {
            printf("cannot watch value of size %d (hardware watchpoints "
                   "support 1, 2, 4, or 8 bytes; use /1, /2, /4, or /8 "
                   "to override)\n", size);
            return;
        }
    }

    int slot = wp_count;

    if (arm_watch_slot(slot, addr, size, access_mode) != 0)
        return;

    watchpoint_t *wp = &watchpoints[slot];

    wp->enabled = 1;
    wp->addr = addr;
    wp->size = size;
    wp->access_mode = access_mode;
    wp->type_off = type_off;
    wp->value = mask_for_size(size, read_memory(addr));
    strncpy(wp->expr, label, sizeof(wp->expr) - 1);
    wp->expr[sizeof(wp->expr) - 1] = '\0';

    wp_count++;

    printf("Hardware %swatchpoint %d: %s\n",
           access_mode ? "access (read/write) " : "", wp_count, wp->expr);
}

void show_watchpoints(void)
{
    if (wp_count == 0) {
        printf("no watchpoints\n");
        return;
    }

    printf("Num  Enb  Address            Size  Mode   What\n");

    for (int i = 0; i < wp_count; i++) {
        watchpoint_t *wp = &watchpoints[i];

        printf("%-4d %-4s 0x%-16lx %-5d %-6s %s\n",
               i + 1,
               wp->enabled ? "y" : "n",
               wp->addr,
               wp->size,
               wp->access_mode ? "rw" : "w",
               wp->expr);
    }
}

int delete_watchpoint(int num)
{
    if (num < 1 || num > wp_count) {
        printf("invalid watchpoint number: %d\n", num);
        return -1;
    }

    disarm_watch_slot(num - 1);

    /* Shift remaining watchpoints down a slot, re-arming each so its
     * debug register index matches its new array position. */
    for (int i = num - 1; i < wp_count - 1; i++) {
        watchpoints[i] = watchpoints[i + 1];
        arm_watch_slot(i, watchpoints[i].addr, watchpoints[i].size,
                       watchpoints[i].access_mode);
    }

    disarm_watch_slot(wp_count - 1);
    wp_count--;
    printf("Watchpoint %d deleted\n", num);
    return 0;
}

/* Checks the debug-register status (DR6) for a hardware watchpoint hit.
 * Returns 0 if this trap wasn't caused by a watchpoint, 1 if a watched
 * value actually changed (already reported; caller should stop), or 2
 * if a watchpoint fired but the value is unchanged (caller should
 * silently resume, mirroring heap-hook transparency). */
static int check_watchpoints(struct user_regs_struct *regs)
{
    if (wp_count == 0)
        return 0;

    long dr6 = peek_debugreg(6);

    if (dr6 == -1)
        return 0;

    /* Bits 0-3 (B0-B3) flag which slot triggered; bits 4-13 are reserved
     * and hard-wired to 1 by the CPU, so they must be masked out or
     * every trap (INT3, single-step, ...) would look like a hit here. */
    long hit_mask = dr6 & 0xFL;

    if (hit_mask == 0)
        return 0;

    int changed = 0;

    for (int i = 0; i < wp_count; i++) {
        if (!(hit_mask & (1L << i)) || !watchpoints[i].enabled)
            continue;

        watchpoint_t *wp = &watchpoints[i];
        long new_value = mask_for_size(wp->size, read_memory(wp->addr));
        int value_changed = (new_value != wp->value);

        /* A write-only watchpoint that fires with no actual value
         * change is spurious (e.g. the same value rewritten) and is
         * silently skipped, like gdb does. An access watchpoint (/r)
         * must still be reported on a bare read, which by definition
         * never changes the value, so it is always reported instead. */
        if (!wp->access_mode && !value_changed)
            continue;

        printf("\nHardware %swatchpoint %d: %s\n\n",
               wp->access_mode ? "access (read/write) " : "",
               i + 1, wp->expr);
        print_watch_value("Old value", (unsigned long)wp->value, wp->type_off);
        print_watch_value("New value", (unsigned long)new_value, wp->type_off);
        wp->value = new_value;
        changed = 1;
    }

    poke_debugreg(6, 0);

    if (changed) {
        show_stop_location(regs->rip);
        return 1;
    }

    return 2;
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

/* Internal temp breakpoint used by next_line() to silently skip over a
 * `call` instruction (run to its return address) without ending the
 * enclosing `next` step. Unlike next_bp/finish_bp, reaching it is never
 * reported to the user. */
static finish_bp_t step_over_bp = {0};

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

void kill_process(void)
{
    if (!dbg.running) {
        printf("no process\n");
        return;
    }

    disarm_temp_breakpoint(&next_bp);
    disarm_temp_breakpoint(&finish_bp);
    disarm_temp_breakpoint(&step_over_bp);
    heap_disarm_hooks();

    kill(dbg.pid, SIGKILL);

    int status;

    do {
        waitpid(dbg.pid, &status, 0);
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));

    wp_count = 0;
    dbg.running = 0;
    printf("[+] process killed (pid=%d)\n", dbg.pid);
}

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

/* Detects a `call` opcode at *addr (near-relative 0xE8, or near-indirect
 * 0xFF /2 or /3). REX-prefixed indirect calls (e.g. through r8-r15) are
 * not recognized and fall back to plain single-stepping into the callee. */
static int insn_is_call(unsigned long addr)
{
    long insn = read_memory(addr);

    if (insn == -1)
        return 0;

    unsigned char op = (unsigned char)insn;
    unsigned char modrm = (unsigned char)(insn >> 8);

    if (op == 0xe8)
        return 1;

    if (op == 0xff && ((modrm >> 3) & 7) == 2)
        return 1;

    if (op == 0xff && ((modrm >> 3) & 7) == 3)
        return 1;

    return 0;
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

    const char *start_file;
    int start_line;

    if (lookup_line(regs.rip, &start_file, &start_line) != 0) {
        printf("no line info\n");
        return;
    }

    unsigned long start_rsp = regs.rsp;

    for (int i = 0; i < 100000; i++) {
        int is_call = insn_is_call(regs.rip);

        if (ptrace(PTRACE_SINGLESTEP, dbg.pid, 0, 0) == -1) {
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

        if (is_call) {
            /* Just entered a callee: run to its return address instead
             * of single-stepping through it, so calls (e.g. into libc)
             * are skipped efficiently while breakpoints/heap hooks
             * encountered along the way are still honored. */
            long ret_addr = read_memory(regs.rsp);

            if (ret_addr != -1 &&
                arm_temp_breakpoint(&step_over_bp,
                                     (unsigned long)ret_addr) == 0) {
                continue_execution();

                if (!dbg.running)
                    return;

                ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs);

                if (regs.rip != (unsigned long long)ret_addr) {
                    /* continue_execution stopped at some other event
                     * (a real breakpoint inside the call, or a signal)
                     * before reaching the return address, and already
                     * reported it; end this `next` here too. */
                    disarm_temp_breakpoint(&step_over_bp);
                    return;
                }
            }
        }

        const char *file;
        int line;
        int changed = lookup_line(regs.rip, &file, &line) != 0 ||
                      line != start_line || strcmp(file, start_file);

        /* Stop once we reach a different line at the same or a shallower
         * stack depth than where we started (covers both a straight
         * line-to-line advance and returning from the function). Ignore
         * line changes while still deeper in an unrecognized callee. */
        if (changed && regs.rsp >= start_rsp) {
            printf("[+] next line at 0x%llx\n", regs.rip);
            show_pc_location(regs.rip);
            return;
        }
    }

    printf("next line limit reached\n");
}

void continue_execution()
{
    if (!dbg.running) {
        printf("no process\n");
        return;
    }

    for (;;) {
        ptrace(
            PTRACE_CONT,
            dbg.pid,
            0,
            0
        );

        int status;
        pid_t ret;

        do {
            ret = waitpid(dbg.pid, &status, 0);
        } while (ret == -1 && errno == EINTR);

        if (WIFEXITED(status)) {
            disarm_temp_breakpoint(&next_bp);
            disarm_temp_breakpoint(&finish_bp);
            disarm_temp_breakpoint(&step_over_bp);
            heap_on_process_exit();
            heap_disarm_hooks();
            wp_count = 0; /* debug registers are per-process; the dead
                           * tracee's slots no longer exist */
            printf("[+] process exited\n");
            dbg.running = 0;
            return;
        }

        if (!WIFSTOPPED(status))
            return;

        int sig = WSTOPSIG(status);

        if (sig != SIGTRAP) {
            struct user_regs_struct regs;

            ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs);

            disarm_temp_breakpoint(&next_bp);
            disarm_temp_breakpoint(&finish_bp);
            disarm_temp_breakpoint(&step_over_bp);

            printf(
                "[+] stopped signal=%d\n",
                sig
            );
            show_stop_location(regs.rip);
            return;
        }

        struct user_regs_struct regs;

        ptrace(
            PTRACE_GETREGS,
            dbg.pid,
            0,
            &regs
        );

        int wp_status = check_watchpoints(&regs);

        if (wp_status == 1)
            return;
        if (wp_status == 2)
            continue;

        if (heap_handle_finish_trap(&regs))
            continue;

        if (heap_handle_trap(&regs))
            continue;

        if (step_over_bp.active &&
            regs.rip - 1 == step_over_bp.addr) {
            handle_temp_stop(&step_over_bp);
            return;
        }

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
            disarm_temp_breakpoint(&step_over_bp);

            printf(
                "[+] breakpoint hit 0x%lx\n",
                bp->addr
            );
            show_stop_location(bp->addr);

            if (step_over_breakpoint(bp) != 0)
                printf("[-] failed to re-enable breakpoint\n");

            return;
        }

        printf(
            "[+] stopped signal=%d\n",
            sig
        );
        show_stop_location(regs.rip);
        return;
    }
}
