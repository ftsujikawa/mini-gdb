#include "dbg.h"
#include "heap.h"

#include <sys/syscall.h>

#define PTRACE_EVENT_FORK 1
#define PTRACE_EVENT_VFORK 2
#define PTRACE_EVENT_CLONE 3
#define PTRACE_EVENT_EXEC 4

/* Scheduler lock: while set to a nonzero tid, `continue_execution`'s
 * resume step only resumes that exact tid. Every other tracked thread
 * (in this or any other tracked process) stays stopped; si/s/n/up
 * refuse to run a non-locked tid outright (see single_step() etc.),
 * so this invariant never needs an exception for whatever tid happens
 * to be currently selected. */
static pid_t locked_tid = 0;

static int wait_for_exec(pid_t pid)
{
    /* TRACEFORK/TRACEVFORK: the debuggee calling fork()/vfork() is
     * assumed to keep running the same executable in the child (no
     * execve() tracking), so its child process is treated the same
     * way TRACECLONE already treats a new thread - discovered and
     * added to threads[], just as its own process (pid == tid) rather
     * than joining an existing one. These options are inherited by
     * further descendants automatically (see ptrace(2)), so this only
     * needs to be set once, here. */
    ptrace(PTRACE_SETOPTIONS, pid, 0,
           PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE |
           PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK);

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
    /* Without this, a `run` issued while a debuggee is already active
     * would just fork a second, wholly independent one on top of it:
     * dbg/threads[] gets overwritten to track only the new one, while
     * the old one is never killed and keeps running in the
     * background sharing this same terminal - visibly garbling output
     * from both processes interleaved together. */
    if (dbg.running)
        kill_process();

    dbg.is_pie = 0;
    dbg.load_base = 0;
    wp_count = 0; /* hardware watchpoints don't survive across processes */
    locked_tid = 0;

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
    dbg.current_tid = pid;
    thread_count = 1;
    threads[0].tid = pid;
    threads[0].pid = pid;
    threads[0].active = 1;
    threads[0].running = 0;

    heap_reset();
    if (heap_trace_enabled())
        heap_arm_hooks();

    printf("[+] process started pid=%d\n", pid);
}

static int find_thread_index(pid_t tid)
{
    for (int i = 0; i < thread_count; i++) {
        if (threads[i].active && threads[i].tid == tid)
            return i;
    }

    return -1;
}

/* Which process (tgid) a tracked tid belongs to, or 0 if `tid` isn't
 * currently tracked. Used by ui.c's show_stop_location() to report the
 * actual process a stop pertains to, rather than always dbg.pid. */
pid_t process_of_tid(pid_t tid)
{
    int idx = find_thread_index(tid);

    return idx >= 0 ? threads[idx].pid : 0;
}

/* `pid` is the thread group (process) `tid` belongs to; pass 0 if not
 * yet known (e.g. a SIGSTOP observed before the CLONE/FORK/VFORK event
 * that would have supplied it) - it gets filled in later, whenever
 * that authoritative event is processed, by the reconciliation below.
 * Until reconciled, a pid-dependent operation (tgkill, SIGKILL, ...) on
 * this tid is simply not attempted; this is the same kind of narrow,
 * self-healing race window that thread registration already tolerates
 * elsewhere in this file. */
static int add_thread(pid_t tid, pid_t pid)
{
    int idx = find_thread_index(tid);

    if (idx >= 0) {
        if (pid != 0 && threads[idx].pid == 0)
            threads[idx].pid = pid;
        return 0;
    }

    if (thread_count >= MAX_THREADS) {
        printf("[-] too many threads (max %d), not tracking tid=%d\n",
               MAX_THREADS, tid);
        return -1;
    }

    threads[thread_count].tid = tid;
    threads[thread_count].pid = pid;
    threads[thread_count].active = 1;
    threads[thread_count].running = 0;
    thread_count++;
    return 0;
}

/* Removes a thread that has exited. If it was the current thread,
 * falls back to whichever thread is now first in the table. */
static void remove_thread(pid_t tid)
{
    int idx = find_thread_index(tid);

    if (idx < 0)
        return;

    for (int i = idx; i < thread_count - 1; i++)
        threads[i] = threads[i + 1];

    thread_count--;

    if (dbg.current_tid == tid && thread_count > 0)
        dbg.current_tid = threads[0].tid;

    if (locked_tid == tid) {
        /* The locked thread just exited. Clear the lock and, since the
         * resume loop at the top of continue_execution() only resumed
         * the locked tid (leaving everyone else stopped with running=0),
         * wake those other threads up now - otherwise they'd stay
         * parked forever and this wait loop would hang waiting for
         * events that can never arrive. */
        printf("[+] locked tid=%d exited; scheduler lock cleared\n", tid);
        locked_tid = 0;

        for (int i = 0; i < thread_count; i++) {
            if (!threads[i].running) {
                ptrace(PTRACE_CONT, threads[i].tid, 0, 0);
                threads[i].running = 1;
            }
        }
    }
}

void show_threads(void)
{
    if (thread_count == 0) {
        printf("no threads\n");
        return;
    }

    printf("   Id  Pid      Tid      Location\n");

    for (int i = 0; i < thread_count; i++) {
        printf("%s%s %-3d %-8d %-8d ",
               threads[i].tid == dbg.current_tid ? "*" : " ",
               locked_tid != 0 && threads[i].tid == locked_tid ? "L" : " ",
               i + 1,
               threads[i].pid,
               threads[i].tid);

        struct user_regs_struct regs;

        if (ptrace(PTRACE_GETREGS, threads[i].tid, 0, &regs) != 0) {
            printf("(unknown)\n");
            continue;
        }

        const symbol_t *sym = lookup_function_symbol(regs.rip);
        unsigned long debug_addr = to_debug_addr(regs.rip);
        const char *file;
        int line;

        printf("0x%016llx", regs.rip);

        if (sym) {
            printf(" in %s", sym->name);

            if (debug_addr >= sym->addr)
                printf("+0x%lx", debug_addr - sym->addr);
        }

        if (lookup_line(regs.rip, &file, &line) == 0)
            printf(" at %s:%d", file, line);

        printf("\n");
    }

    if (locked_tid != 0)
        printf("(L = locked; only this tid runs on `c`)\n");
}

int switch_thread(int num)
{
    if (num < 1 || num > thread_count) {
        printf("invalid thread number: %d\n", num);
        return -1;
    }

    dbg.current_tid = threads[num - 1].tid;
    printf("[+] switched to thread %d (tid=%d)\n", num, dbg.current_tid);

    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, dbg.current_tid, 0, &regs) == 0)
        show_stop_location(regs.rip);

    return 0;
}

void lock_thread(int tid)
{
    if (!dbg.running) {
        printf("no process\n");
        return;
    }

    if (find_thread_index((pid_t)tid) < 0) {
        printf("no such tid: %d (use 'threads' to list them)\n", tid);
        return;
    }

    locked_tid = (pid_t)tid;
    dbg.current_tid = locked_tid;

    printf("[+] locked to tid=%d (other threads stay stopped on `c`)\n",
           locked_tid);

    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, dbg.current_tid, 0, &regs) == 0)
        show_stop_location(regs.rip);
}

void unlock_threads(void)
{
    if (locked_tid == 0) {
        printf("not locked\n");
        return;
    }

    printf("[+] unlocked tid=%d (all threads resume on `c`)\n", locked_tid);
    locked_tid = 0;
}

void single_step()
{
    if (!dbg.running) {
        printf("no process\n");
        return;
    }

    if (locked_tid != 0 && dbg.current_tid != locked_tid) {
        printf("current thread (tid=%d) is not the locked thread "
               "(locked to tid=%d); use `thread` to switch back or "
               "`unlock`\n", dbg.current_tid, locked_tid);
        return;
    }

    ptrace(
        PTRACE_SINGLESTEP,
        dbg.current_tid,
        0,
        0
    );

    int status;

    waitpid(
        dbg.current_tid,
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

        ptrace(PTRACE_GETREGS, dbg.current_tid, 0, &regs);
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

    if (locked_tid != 0 && dbg.current_tid != locked_tid) {
        printf("current thread (tid=%d) is not the locked thread "
               "(locked to tid=%d); use `thread` to switch back or "
               "`unlock`\n", dbg.current_tid, locked_tid);
        return;
    }

    struct user_regs_struct regs;
    const char *start_file;
    int start_line;

    ptrace(PTRACE_GETREGS, dbg.current_tid, 0, &regs);

    if (lookup_line(regs.rip, &start_file, &start_line) != 0) {
        single_step();
        return;
    }

    for (int i = 0; i < 10000; i++) {
        if (ptrace(PTRACE_SINGLESTEP,
                   dbg.current_tid,
                   0,
                   0) == -1) {
            perror("ptrace singlestep");
            return;
        }

        int status;

        if (waitpid(dbg.current_tid, &status, 0) < 0) {
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

        ptrace(PTRACE_GETREGS, dbg.current_tid, 0, &regs);

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

    /* INT3 lives in per-process memory, so it must be poked into every
     * tracked process, not just the original one: fork children only
     * inherit (via copy-on-write) INT3 bytes that already existed at
     * fork time, not ones added afterward. A given process can fail
     * here (ESRCH) if it exited a moment ago and hasn't been reaped
     * yet - skip it rather than aborting registration for every
     * other, still-alive process over one that's already gone. */
    for (int i = 0; i < thread_count; i++) {
        if (threads[i].tid != threads[i].pid)
            continue;

        enable_breakpoint_tid(threads[i].pid, bp);
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
        /* INT3 lives in per-process memory, so restore it in every
         * tracked process, not just the original one (fork children
         * each have their own copy). */
        for (int i = 0; i < thread_count; i++) {
            if (threads[i].tid != threads[i].pid)
                continue;

            restore_breakpoint_tid(threads[i].pid, bp);
        }
    }

    /* Shift remaining breakpoints down */
    for (int i = num - 1; i < bp_count - 1; i++)
        breakpoints[i] = breakpoints[i + 1];

    bp_count--;
    printf("Breakpoint %d deleted\n", num);
    return 0;
}

/* Debug registers (DR0-DR7) are per-thread CPU state, not process-wide,
 * so every caller must specify which tid it is reading/writing. */
static long peek_debugreg(pid_t tid, int i)
{
    return ptrace(PTRACE_PEEKUSER, tid,
                  (void *)(offsetof(struct user, u_debugreg[0]) +
                           (size_t)i * sizeof(unsigned long long)),
                  0);
}

static int poke_debugreg(pid_t tid, int i, unsigned long val)
{
    return ptrace(PTRACE_POKEUSER, tid,
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

static int arm_watch_slot(pid_t tid, int slot, unsigned long addr, int size,
                           int access_mode)
{
    if (poke_debugreg(tid, slot, addr) == -1) {
        perror("ptrace poke debugreg");
        return -1;
    }

    long dr7 = peek_debugreg(tid, 7);

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

    if (poke_debugreg(tid, 7, (unsigned long)dr7) == -1) {
        perror("ptrace poke debugreg");
        return -1;
    }

    return 0;
}

static void disarm_watch_slot(pid_t tid, int slot)
{
    long dr7 = peek_debugreg(tid, 7);

    if (dr7 == -1)
        return;

    dr7 &= ~(0x3L << (slot * 2));
    poke_debugreg(tid, 7, (unsigned long)dr7);
}

/* Applies every currently-armed watchpoint's debug-register state to a
 * newly created thread, so hardware watchpoints (which are per-thread)
 * keep covering the whole process rather than just the thread that was
 * current when `watch` was issued. */
static void propagate_watchpoints_to_thread(pid_t tid)
{
    for (int i = 0; i < wp_count; i++) {
        if (watchpoints[i].enabled)
            arm_watch_slot(tid, i, watchpoints[i].addr,
                           watchpoints[i].size, watchpoints[i].access_mode);
    }
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

    ptrace(PTRACE_GETREGS, dbg.current_tid, 0, &regs);

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

    /* A watchpoint covers the whole process, not just the thread that
     * was current when it was set, so every thread's debug registers
     * for this slot must be armed (new threads pick it up via
     * propagate_watchpoints_to_thread when they are created). A given
     * tid can fail here (ESRCH) if it exited a moment ago and hasn't
     * been reaped yet - that thread can never write anything again,
     * so skip it rather than aborting registration for every other,
     * still-alive thread over one that's already gone. */
    for (int i = 0; i < thread_count; i++)
        arm_watch_slot(threads[i].tid, slot, addr, size, access_mode);

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

    for (int t = 0; t < thread_count; t++)
        disarm_watch_slot(threads[t].tid, num - 1);

    /* Shift remaining watchpoints down a slot, re-arming each (on every
     * thread) so its debug register index matches its new array
     * position. */
    for (int i = num - 1; i < wp_count - 1; i++) {
        watchpoints[i] = watchpoints[i + 1];

        for (int t = 0; t < thread_count; t++)
            arm_watch_slot(threads[t].tid, i, watchpoints[i].addr,
                           watchpoints[i].size, watchpoints[i].access_mode);
    }

    for (int t = 0; t < thread_count; t++)
        disarm_watch_slot(threads[t].tid, wp_count - 1);

    wp_count--;
    printf("Watchpoint %d deleted\n", num);
    return 0;
}

/* Checks the debug-register status (DR6) for a hardware watchpoint hit.
 * Returns 0 if this trap wasn't caused by a watchpoint, 1 if a watched
 * value actually changed (already reported; caller should stop), or 2
 * if a watchpoint fired but the value is unchanged (caller should
 * silently resume, mirroring heap-hook transparency). */
static int check_watchpoints(pid_t tid, struct user_regs_struct *regs)
{
    if (wp_count == 0)
        return 0;

    long dr6 = peek_debugreg(tid, 6);

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
        long new_value = mask_for_size(wp->size, read_memory_tid(tid, wp->addr));
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

    poke_debugreg(tid, 6, 0);

    if (changed) {
        /* Must happen before show_stop_location(), which reports
         * dbg.current_tid - otherwise a watchpoint hit on some other
         * (non-current) tid/process would misreport whichever tid was
         * previously selected instead of the one that actually hit. */
        dbg.current_tid = tid;
        show_stop_location(regs->rip);
        return 1;
    }

    return 2;
}

int restore_breakpoint_tid(pid_t tid, breakpoint_t *bp)
{
    if (ptrace(
            PTRACE_POKEDATA,
            tid,
            (void*)bp->addr,
            (void*)bp->original_data
        ) == -1) {
        perror("ptrace restore breakpoint");
        return -1;
    }

    return 0;
}

int enable_breakpoint_tid(pid_t tid, breakpoint_t *bp)
{
    long patched =
        (bp->original_data & ~0xff) | 0xcc;

    if (ptrace(
            PTRACE_POKEDATA,
            tid,
            (void*)bp->addr,
            (void*)patched
        ) == -1) {
        perror("ptrace enable breakpoint");
        return -1;
    }

    return 0;
}

void rewind_rip(pid_t tid, unsigned long addr)
{
    struct user_regs_struct regs;

    ptrace(
        PTRACE_GETREGS,
        tid,
        0,
        &regs
    );

    regs.rip = addr;

    ptrace(
        PTRACE_SETREGS,
        tid,
        0,
        &regs
    );
}

int step_over_breakpoint(pid_t tid, breakpoint_t *bp)
{
    /*
      restore original instruction
    */

    if (restore_breakpoint_tid(tid, bp) != 0)
        return -1;

    /*
      RIP = original address
    */

    rewind_rip(tid, bp->addr);

    /*
     * Execute exactly 1 instruction. A signal queued for this tid from
     * elsewhere (e.g. the directed SIGSTOP sent by
     * sync_stop_other_threads for all-stop synchronization) can preempt
     * the singlestep: the tracee re-stops immediately without actually
     * executing anything, rip unchanged. Since rip is already known-good
     * (just rewound above) and the INT3 has already been removed, it is
     * always safe to just retry in that case.
     */
    for (int attempt = 0; attempt < 10; attempt++) {
        if (ptrace(
                PTRACE_SINGLESTEP,
                tid,
                0,
                0
            ) == -1) {
            perror("ptrace singlestep");
            enable_breakpoint_tid(tid, bp);
            return -1;
        }

        int status;

        if (waitpid(
                tid,
                &status,
                __WALL
            ) < 0) {
            perror("waitpid");
            return -1;
        }

        if (WIFEXITED(status)) {
            printf("[+] process exited\n");
            dbg.running = 0;
            return -1;
        }

        if (!WIFSTOPPED(status))
            continue;

        struct user_regs_struct regs;

        if (ptrace(PTRACE_GETREGS, tid, 0, &regs) == 0 &&
            regs.rip != bp->addr)
            break; /* actually advanced past the original instruction */

        /* Preempted before the instruction executed; retry. */
    }

    /*
      put INT3 back
    */

    if (enable_breakpoint_tid(tid, bp) != 0)
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
    /* Recorded up front (rather than relying on dbg.current_tid later)
     * so disarm/handle still target the right thread/process even if
     * dbg.current_tid gets reassigned in between - e.g. some other,
     * unrelated tid hitting its own breakpoint while this one is
     * pending. */
    tp->tid = dbg.current_tid;

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
               tp->tid,
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
            tp->tid,
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
            tp->tid,
            (void *)tp->addr,
            (void *)tp->original_data
        );
    }

    unsigned long addr = tp->addr;

    rewind_rip(tp->tid, addr);
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

    ptrace(PTRACE_GETREGS, dbg.current_tid, 0, &regs);

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

    /* SIGKILL targets one thread group (tgid) at a time; with fork()
     * children tracked, that may be more than just dbg.pid. */
    for (int i = 0; i < thread_count; i++) {
        if (threads[i].tid == threads[i].pid)
            kill(threads[i].pid, SIGKILL);
    }

    /* SIGKILL brings down each thread group, but every thread still
     * produces its own wait event; reap all of them so none are left as
     * zombies. */
    int remaining = thread_count;

    while (remaining > 0) {
        int status;
        pid_t tid = waitpid(-1, &status, __WALL);

        if (tid == -1) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status))
            remaining--;
    }

    wp_count = 0;
    thread_count = 0;
    locked_tid = 0;
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

    if (locked_tid != 0 && dbg.current_tid != locked_tid) {
        printf("current thread (tid=%d) is not the locked thread "
               "(locked to tid=%d); use `thread` to switch back or "
               "`unlock`\n", dbg.current_tid, locked_tid);
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

    if (locked_tid != 0 && dbg.current_tid != locked_tid) {
        printf("current thread (tid=%d) is not the locked thread "
               "(locked to tid=%d); use `thread` to switch back or "
               "`unlock`\n", dbg.current_tid, locked_tid);
        return;
    }

    pid_t tid = dbg.current_tid;
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, tid, 0, &regs);

    const char *start_file;
    int start_line;

    if (lookup_line(regs.rip, &start_file, &start_line) != 0) {
        printf("no line info\n");
        return;
    }

    unsigned long start_rsp = regs.rsp;

    for (int i = 0; i < 100000; i++) {
        int is_call = insn_is_call(regs.rip);

        if (ptrace(PTRACE_SINGLESTEP, tid, 0, 0) == -1) {
            perror("ptrace singlestep");
            return;
        }

        int status;

        if (waitpid(tid, &status, 0) < 0) {
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

        ptrace(PTRACE_GETREGS, tid, 0, &regs);

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

                if (dbg.current_tid != tid) {
                    /* A different thread reported a real stop event
                     * (breakpoint/watchpoint/signal) during the call
                     * skip and already took over the prompt; end this
                     * `next` here too. */
                    disarm_temp_breakpoint(&step_over_bp);
                    return;
                }

                ptrace(PTRACE_GETREGS, tid, 0, &regs);

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

/* If `tid` is currently parked right after a real breakpoint's INT3, steps
 * it over properly (restore original bytes, replay the real instruction,
 * re-arm the INT3) so it is never left sitting mid-instruction - which
 * would corrupt its execution the next time it resumes (the breakpoint
 * may since have been deleted, restoring the original bytes while this
 * tid's rip is still one byte into them). Safe to call for any tid that
 * is currently ptrace-stopped, known to us or not. Returns 1 if a
 * breakpoint was found and handled (which also consumes/retries past any
 * signal that was queued for this tid), 0 if it wasn't parked on one. */
static int step_over_if_pending_breakpoint(pid_t tid)
{
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, tid, 0, &regs) != 0)
        return 0;

    breakpoint_t *bp = find_breakpoint_by_rip(regs.rip);

    if (!bp)
        return 0;

    step_over_breakpoint(tid, bp);
    return 1;
}

/* Recognizes a PTRACE_EVENT_CLONE/FORK/VFORK notification riding on a
 * SIGTRAP stop for `tid`, registers the new tid/process it reports
 * (via PTRACE_GETEVENTMSG), and resumes `tid` past it. Returns 1 if
 * `status` was such a notification (fully handled here); 0 otherwise,
 * meaning the caller still needs to figure out what this stop was.
 * Shared between continue_execution()'s main dispatch and
 * sync_stop_other_threads(): a thread being forced to stop for
 * synchronization can just as easily be the one that happens to
 * create a new thread/process at that exact moment, and discarding
 * that notification (as the generic "some other stop reason, not a
 * breakpoint" fallback would) permanently loses the new tid's pid. */
static int handle_new_thread_event(pid_t tid, int status)
{
    if (WSTOPSIG(status) != SIGTRAP)
        return 0;

    int event = (status >> 16) & 0xffff;

    if (event == PTRACE_EVENT_CLONE) {
        unsigned long new_tid_word = 0;

        if (ptrace(PTRACE_GETEVENTMSG, tid, 0, &new_tid_word) == 0) {
            int parent_idx = find_thread_index(tid);

            add_thread((pid_t)new_tid_word,
                       parent_idx >= 0 ? threads[parent_idx].pid : 0);
        }

        ptrace(PTRACE_CONT, tid, 0, 0);
        return 1;
    }

    if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK) {
        unsigned long new_pid_word = 0;

        if (ptrace(PTRACE_GETEVENTMSG, tid, 0, &new_pid_word) == 0)
            add_thread((pid_t)new_pid_word, (pid_t)new_pid_word);

        ptrace(PTRACE_CONT, tid, 0, 0);
        return 1;
    }

    return 0;
}

/* All-stop synchronization: once one thread has a genuine stop event to
 * report, every other still-running thread is forced to stop too (via a
 * directed SIGSTOP) so the whole process is halted at the prompt, matching
 * gdb's default all-stop behavior. Their individual stop reasons are not
 * processed here; the user can inspect them with `threads`/`thread <n>`. */
static void sync_stop_other_threads(pid_t stopped_tid)
{
    int pending = 0;

    for (int i = 0; i < thread_count; i++) {
        if (threads[i].tid == stopped_tid) {
            threads[i].running = 0;
            continue;
        }

        if (threads[i].running) {
            /* tgkill needs the tid's OWN thread group, which may be a
             * fork()ed child's pid rather than dbg.pid. */
            syscall(SYS_tgkill, threads[i].pid, threads[i].tid, SIGSTOP);
            pending++;
        }
    }

    while (pending > 0) {
        int status;
        pid_t tid;

        do {
            tid = waitpid(-1, &status, __WALL);
        } while (tid == -1 && errno == EINTR);

        if (tid == -1)
            break;

        int idx = find_thread_index(tid);

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (idx >= 0 && threads[idx].running)
                pending--;
            remove_thread(tid);
            continue;
        }

        if (!WIFSTOPPED(status))
            continue;

        int sig = WSTOPSIG(status);

        if (idx < 0) {
            /* Thread not yet registered - its parent's clone/fork
             * notification hasn't reached the main dispatch loop yet.
             * Register it now (pid unknown for the moment - it will
             * be filled in once that notification is processed) and
             * make sure it isn't left parked mid-breakpoint; it never
             * counted against `pending` since we never explicitly
             * stopped it. */
            add_thread(tid, 0);

            if (sig != SIGSTOP)
                step_over_if_pending_breakpoint(tid);

            continue;
        }

        if (!threads[idx].running)
            continue;

        threads[idx].running = 0;
        pending--;

        if (sig != SIGSTOP) {
            if (handle_new_thread_event(tid, status)) {
                /* tid just created a new thread/process, not stopped
                 * for a reportable reason of its own; undo the
                 * running=0/pending-- above and keep waiting for its
                 * real subsequent stop (most likely the SIGSTOP sent
                 * to it above, still queued). */
                threads[idx].running = 1;
                pending++;
                continue;
            }

            /* This thread stopped for its own reason (e.g. it hit the
             * same breakpoint/watchpoint at nearly the same moment as
             * stopped_tid), not because of the SIGSTOP just sent to
             * it. If it was parked on a breakpoint, step_over_* has
             * already internally retried past any preemption from that
             * queued SIGSTOP, so nothing more is needed - the thread is
             * left properly stopped. Otherwise, the SIGSTOP is still
             * queued and would otherwise fire as a spurious stop right
             * after this thread is next resumed, so resume-and-reabsorb
             * it explicitly here instead. */
            if (!step_over_if_pending_breakpoint(tid)) {
                ptrace(PTRACE_CONT, tid, 0, 0);

                int drain_status;
                pid_t drained;

                do {
                    drained = waitpid(tid, &drain_status, __WALL);
                } while (drained == -1 && errno == EINTR);

                if (drained == tid &&
                    (WIFEXITED(drain_status) || WIFSIGNALED(drain_status)))
                    remove_thread(tid);
                /* Otherwise the thread is stopped again (whether the
                 * drained event was the queued SIGSTOP or something
                 * else) - leave it as-is; best effort. */
            }
        }
    }
}

void continue_execution()
{
    if (!dbg.running) {
        printf("no process\n");
        return;
    }

    for (int i = 0; i < thread_count; i++) {
        /* Under a scheduler lock, only the locked tid gets resumed;
         * every other thread is left stopped, with no exception for
         * whatever tid happens to be currently selected. Callers that
         * drive continue_execution() for a non-locked tid (next_line's
         * step-over-a-call, finish_function) must check the lock
         * themselves before ever getting here, or this would deadlock
         * waiting for a thread that never resumes. */
        if (locked_tid != 0 && threads[i].tid != locked_tid)
            continue;

        ptrace(PTRACE_CONT, threads[i].tid, 0, 0);
        threads[i].running = 1;
    }

    for (;;) {
        int status;
        pid_t tid;

        do {
            tid = waitpid(-1, &status, __WALL);
        } while (tid == -1 && errno == EINTR);

        if (tid == -1) {
            perror("waitpid");
            return;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            int idx = find_thread_index(tid);
            int was_process_root = (idx >= 0 && threads[idx].pid == tid);

            remove_thread(tid);

            if (thread_count == 0) {
                /* Every tracked process's every thread is now gone
                 * (not just dbg.pid's - a fork()ed child may outlive
                 * or outnumber the original process's threads). */
                disarm_temp_breakpoint(&next_bp);
                disarm_temp_breakpoint(&finish_bp);
                disarm_temp_breakpoint(&step_over_bp);
                heap_on_process_exit();
                heap_disarm_hooks();
                wp_count = 0; /* debug registers are per-process; the dead
                               * tracee's slots no longer exist */
                locked_tid = 0;
                printf("[+] process exited\n");
                dbg.running = 0;
                return;
            }

            /* This process is gone but at least one other tracked
             * process/thread remains; keep waiting. */
            if (was_process_root)
                printf("[+] process pid=%d exited "
                       "(other tracked processes remain)\n", tid);
            continue;
        }

        if (!WIFSTOPPED(status))
            continue;

        int sig = WSTOPSIG(status);

        /* New thread (CLONE) or new process (FORK/VFORK): register it
         * here and resume the reporting tid past the notification. Do
         * NOT resume the newly reported tid/pid itself yet - its own
         * initial ptrace-stop (delivered as SIGSTOP, handled below)
         * may not have been reaped yet, and the two notifications can
         * arrive in either order; the SIGSTOP handler is the single
         * place that actually CONTs a freshly-registered tid once its
         * stop is confirmed. A forked child's memory is a fork-time
         * copy of the parent's, so any breakpoint already set is
         * already physically present (copy-on-write) - only ones set
         * *after* this need propagating, which set_breakpoint()
         * handles by walking every tracked process; its debug
         * registers, unlike INT3 bytes in memory, are NOT inherited
         * and still need seeding, same as for a cloned thread - both
         * handled by the SIGSTOP branch below. */
        if (handle_new_thread_event(tid, status))
            continue;

        if (sig == SIGSTOP) {
            /* SIGSTOP is never something the debuggee legitimately wants
             * reported: it is either our own sync_stop_other_threads
             * mechanism, or the implicit initial stop of a newly cloned
             * thread or forked process. Track the thread if new, and
             * resume it (seeding its debug registers from any
             * watchpoints already armed) unless it is one we
             * deliberately just stopped and are still collecting via
             * sync_stop_other_threads. */
            add_thread(tid, 0);

            int idx = find_thread_index(tid);

            if (idx >= 0 && !threads[idx].running) {
                propagate_watchpoints_to_thread(tid);

                /* Respect an active scheduler lock: a thread newly
                 * spawned while locked to a different tid must not
                 * start running either. It stays registered but
                 * stopped until `unlock` (or a lock on this tid). */
                if (locked_tid == 0 || tid == locked_tid) {
                    ptrace(PTRACE_CONT, tid, 0, 0);
                    threads[idx].running = 1;
                }
            } else if (idx >= 0 && locked_tid != 0 && tid != locked_tid) {
                /* We believed this tid was running, but a lock now
                 * excludes it - leave it stopped and update our
                 * bookkeeping to match reality. */
                threads[idx].running = 0;
            } else if (idx >= 0) {
                /* Stray SIGSTOP for a tid we already believe is (and
                 * should remain) running: a synchronization signal
                 * from an earlier, already-finished
                 * sync_stop_other_threads round, delivered late -
                 * under CPU contention, delivery of a queued signal
                 * can be delayed arbitrarily, well past the point
                 * where that round moved on and this tid was already
                 * legitimately resumed and doing further work. Once
                 * that happens, nothing else ever revisits an
                 * already-`running` tid, so failing to react here
                 * would leave it parked in this ptrace-stop forever
                 * (verified live: `t`/ptrace_stop in /proc, with its
                 * whole process wedged on it via pthread_join). Absorb
                 * it and resume immediately, exactly like
                 * sync_stop_other_threads's own resume-and-reabsorb
                 * path for this same class of stale signal. */
                ptrace(PTRACE_CONT, tid, 0, 0);
            }

            continue;
        }

        if (sig == SIGCHLD) {
            /* A traced process that manages its own children (e.g. a
             * fork()-based server reaping them via waitpid()) receives
             * its own SIGCHLD whenever one exits; since we intercept
             * every signal delivered to a tracee, that would otherwise
             * stop here and force the user to `c` through one prompt
             * per child exit. gdb's default is to pass SIGCHLD through
             * without stopping, so do the same: forward it and keep
             * going, rather than treating it as a reportable stop. */
            ptrace(PTRACE_CONT, tid, 0, sig);
            continue;
        }

        if (sig != SIGTRAP) {
            struct user_regs_struct regs;

            ptrace(PTRACE_GETREGS, tid, 0, &regs);

            add_thread(tid, 0);
            dbg.current_tid = tid;
            sync_stop_other_threads(tid);

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

        ptrace(PTRACE_GETREGS, tid, 0, &regs);

        int wp_status = check_watchpoints(tid, &regs);

        if (wp_status == 1) {
            add_thread(tid, 0);
            dbg.current_tid = tid;
            sync_stop_other_threads(tid);
            return;
        }

        if (wp_status == 2) {
            ptrace(PTRACE_CONT, tid, 0, 0);
            continue;
        }

        if (heap_handle_finish_trap(&regs)) {
            ptrace(PTRACE_CONT, tid, 0, 0);
            continue;
        }

        if (heap_handle_trap(&regs)) {
            ptrace(PTRACE_CONT, tid, 0, 0);
            continue;
        }

        if (tid == dbg.current_tid && step_over_bp.active &&
            regs.rip - 1 == step_over_bp.addr) {
            handle_temp_stop(&step_over_bp);
            sync_stop_other_threads(tid);
            return;
        }

        if (tid == dbg.current_tid && next_bp.active &&
            regs.rip - 1 == next_bp.addr) {
            handle_next_hit();
            sync_stop_other_threads(tid);
            return;
        }

        if (tid == dbg.current_tid && finish_bp.active &&
            regs.rip - 1 == finish_bp.addr) {
            handle_finish_hit();
            sync_stop_other_threads(tid);
            return;
        }

        breakpoint_t *bp =
            find_breakpoint_by_rip(
                regs.rip
            );

        if (bp) {
            add_thread(tid, 0); /* defensive: in case its clone/fork
                                  * notification hasn't been processed
                                  * yet */
            dbg.current_tid = tid;
            sync_stop_other_threads(tid);

            disarm_temp_breakpoint(&next_bp);
            disarm_temp_breakpoint(&finish_bp);
            disarm_temp_breakpoint(&step_over_bp);

            printf(
                "[+] breakpoint hit 0x%lx\n",
                bp->addr
            );
            show_stop_location(bp->addr);

            if (step_over_breakpoint(tid, bp) != 0)
                printf("[-] failed to re-enable breakpoint\n");

            return;
        }

        /* Unrecognized SIGTRAP on a thread we're not actively
         * stepping/finishing (e.g. a stray singlestep trap on another
         * thread) - resume it silently rather than stalling `c`. */
        if (tid != dbg.current_tid) {
            ptrace(PTRACE_CONT, tid, 0, 0);
            continue;
        }

        dbg.current_tid = tid;
        sync_stop_other_threads(tid);
        printf(
            "[+] stopped signal=%d\n",
            sig
        );
        show_stop_location(regs.rip);
        return;
    }
}
