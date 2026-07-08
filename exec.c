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
            heap_on_process_exit();
            heap_disarm_hooks();
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

        if (heap_handle_finish_trap(&regs))
            continue;

        if (heap_handle_trap(&regs))
            continue;

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

        printf(
            "[+] stopped signal=%d\n",
            sig
        );
        show_stop_location(regs.rip);
        return;
    }
}
