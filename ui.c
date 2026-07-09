#include "dbg.h"
#include "cmd.h"

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

void show_stop_location(unsigned long pc)
{
    const char *file;
    int line;

    /* This debugger only ever tracks a single (main) thread, whose tid
     * equals its pid, so both are reported from dbg.pid. */
    printf("[+] pid=%d tid=%d\n", dbg.pid, dbg.pid);

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
void show_regs()
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

    printf("rax      0x%016llx\n", regs.rax);
    printf("rbx      0x%016llx\n", regs.rbx);
    printf("rcx      0x%016llx\n", regs.rcx);
    printf("rdx      0x%016llx\n", regs.rdx);
    printf("rsi      0x%016llx\n", regs.rsi);
    printf("rdi      0x%016llx\n", regs.rdi);
    printf("rbp      0x%016llx\n", regs.rbp);
    printf("rsp      0x%016llx\n", regs.rsp);
    printf("r8       0x%016llx\n", regs.r8);
    printf("r9       0x%016llx\n", regs.r9);
    printf("r10      0x%016llx\n", regs.r10);
    printf("r11      0x%016llx\n", regs.r11);
    printf("r12      0x%016llx\n", regs.r12);
    printf("r13      0x%016llx\n", regs.r13);
    printf("r14      0x%016llx\n", regs.r14);
    printf("r15      0x%016llx\n", regs.r15);
    printf("rip      0x%016llx\n", regs.rip);
    show_pc_location(regs.rip);
    printf("eflags   0x%016llx\n", regs.eflags);
    printf("orig_rax 0x%016llx\n", regs.orig_rax);
    printf("cs       0x%016llx\n", regs.cs);
    printf("ss       0x%016llx\n", regs.ss);
    printf("ds       0x%016llx\n", regs.ds);
    printf("es       0x%016llx\n", regs.es);
    printf("fs       0x%016llx\n", regs.fs);
    printf("gs       0x%016llx\n", regs.gs);
    printf("fs_base  0x%016llx\n", regs.fs_base);
    printf("gs_base  0x%016llx\n", regs.gs_base);

    struct user_fpregs_struct fpregs;

    if (ptrace(PTRACE_GETFPREGS, dbg.pid, 0, &fpregs) == -1) {
        perror("ptrace getfpregs");
        return;
    }

    printf("\n");
    printf("fctrl      0x%04x\n", fpregs.cwd);
    printf("fstat      0x%04x\n", fpregs.swd);
    printf("ftag       0x%04x\n", fpregs.ftw);
    printf("fop        0x%04x\n", fpregs.fop);
    printf("fioff      0x%016llx\n", fpregs.rip);
    printf("fooff      0x%016llx\n", fpregs.rdp);
    printf("mxcsr      0x%08x\n", fpregs.mxcsr);
    printf("mxcsr_mask 0x%08x\n", fpregs.mxcr_mask);

    for (int i = 0; i < 8; i++) {
        unsigned char bytes[10];
        long double val = 0;

        memcpy(bytes, &fpregs.st_space[i * 4], sizeof(bytes));
        memcpy(&val, &fpregs.st_space[i * 4], sizeof(val));
        printf("st%-2d       0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x  %Lg\n",
               i,
               bytes[9], bytes[8], bytes[7], bytes[6], bytes[5],
               bytes[4], bytes[3], bytes[2], bytes[1], bytes[0], val);
    }

    for (int i = 0; i < 16; i++) {
        unsigned int *x = &fpregs.xmm_space[i * 4];
        double lo, hi;

        memcpy(&lo, &x[0], sizeof(lo));
        memcpy(&hi, &x[2], sizeof(hi));
        printf("xmm%-2d      0x%08x%08x%08x%08x  {v2_double = {%g, %g}}\n",
               i, x[3], x[2], x[1], x[0], lo, hi);
    }
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

void show_help(void)
{
    printf("Commands:\n");
    printf("  run <program>              start debugging a program\n");
    printf("  c                          continue execution\n");
    printf("  s                          step one source line\n");
    printf("  si                         step one instruction\n");
    printf("  n                          step to next source line\n");
    printf("  up                         run until current function returns\n");
    printf("  b|break <loc>              set breakpoint (addr, symbol, file:line)\n");
    printf("  del|delete <num>           delete breakpoint by number\n");
    printf("  show bp                    list breakpoints\n");
    printf("  p|print [/fmt] <expr>      evaluate and print an expression\n");
    printf("  set <name> = <value>       assign variable, register, or setting\n");
    printf("  set $<reg> = <expr>        gpr/eflags/fctrl/fstat/ftag/fop/mxcsr\n");
    printf("  set $<st0-7|xmm0-15> = <v> x87/SSE register (float or hex bits)\n");
    printf("  show [language|print|bp|heap|leaks]   show debugger settings\n");
    printf("  show locals|args|globals   show variables\n");
    printf("  set heap-trace on            track malloc/free in debuggee\n");
    printf("  dbg [vars|var|lines|line]  show DWARF debug info\n");
    printf("  lines [file]               show line number table\n");
    printf("  l|list [loc]               list source code\n");
    printf("  dis <loc>                  disassemble instructions\n");
    printf("  tb                         show backtrace\n");
    printf("  regs                       show registers (gpr, x87, SSE/XMM)\n");
    printf("  syms                       show symbols\n");
    printf("  x <addr>                   examine memory\n");
    printf("  help                       show this help\n");
    printf("  q                          quit\n");
    printf("  Ctrl+C                     interrupt running program\n");
}

void handle(char *line)
{
    cmd_t cmd = {0};
    char err[256];

    if (cmd_parse_line(line, &cmd, err, sizeof(err)) != 0) {
        printf("%s\n", err[0] ? err : "unknown command");
        cmd_free(&cmd);
        return;
    }

    switch (cmd.kind) {
    case CMD_INVALID:
        break;
    case CMD_RUN:
        if (!cmd.arg || !cmd.arg[0]) {
            printf("usage: run <program>\n");
            break;
        }
        run_target(cmd.arg);
        break;
    case CMD_C:
        continue_execution();
        break;
    case CMD_S:
        source_step();
        break;
    case CMD_SI:
        single_step();
        break;
    case CMD_N:
        next_line();
        break;
    case CMD_UP:
        finish_function();
        break;
    case CMD_REGS:
        show_regs();
        break;
    case CMD_SYMS:
        show_symbols();
        break;
    case CMD_TB:
        show_backtrace();
        break;
    case CMD_LIST:
        list_source(cmd.arg ? cmd.arg : "");
        break;
    case CMD_DIS:
        disassemble_command(cmd.arg ? cmd.arg : "");
        break;
    case CMD_BREAK: {
        /* Keep original behavior/errors by reusing old parsing code paths. */
        char buf[256];
        strncpy(buf, cmd.arg ? cmd.arg : "", sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        trim_line(buf);

        if (buf[0] == '\0') {
            printf("usage: b|break <addr|symbol|file:line>\n");
            break;
        }

        unsigned long addr;
        char *colon = strrchr(buf, ':');

        if (colon && colon[1] != '\0') {
            char file[256];
            size_t file_len = (size_t)(colon - buf);

            if (file_len >= sizeof(file)) {
                printf("invalid location: %s\n", buf);
                break;
            }

            memcpy(file, buf, file_len);
            file[file_len] = '\0';

            char *line_end;
            long line_num = strtol(colon + 1, &line_end, 10);

            if (*line_end == '\0' && line_num > 0) {
                if (lookup_line_addr(file, (int)line_num, &addr) == 0) {
                    set_breakpoint(addr);
                } else {
                    printf("no line info for %s:%ld\n", file, line_num);
                }
                break;
            }
        }

        char *end;
        addr = strtoul(buf, &end, 0);

        if (*end == '\0' && end != buf) {
            set_breakpoint(addr);
        } else {
            const symbol_t *sym = lookup_symbol_entry(buf);

            if (!sym) {
                printf("unknown symbol: %s\n", buf);
                break;
            }

            addr = sym->addr;

            if (sym->type == STT_FUNC)
                lookup_function_body_addr(sym, &addr);

            set_breakpoint(addr);
        }
        break;
    }
    case CMD_DEL: {
        char *arg = cmd.arg ? cmd.arg : "";
        char *end;
        long num = strtol(arg, &end, 10);

        if (*end != '\0' || end == arg || num <= 0) {
            printf("usage: del|delete <breakpoint-number>\n");
            printf("       (use 'show b' to list breakpoints)\n");
            break;
        }

        delete_breakpoint((int)num);
        break;
    }
    case CMD_SHOW:
        show_command(cmd.arg ? cmd.arg : "");
        break;
    case CMD_DBG:
        dbg_command(cmd.arg ? cmd.arg : "");
        break;
    case CMD_LINES: {
        char buf[256];
        strncpy(buf, cmd.arg ? cmd.arg : "", sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        trim_line(buf);

        if (buf[0] == '\0')
            show_line_table(NULL);
        else
            show_line_table(buf);
        break;
    }
    case CMD_X: {
        unsigned long addr;
        char buf[256];

        strncpy(buf, cmd.arg ? cmd.arg : "", sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        trim_line(buf);

        if (buf[0] == '\0') {
            printf("usage: x <addr>\n");
            break;
        }

        if (sscanf(buf, "%lx", &addr) != 1) {
            printf("usage: x <addr>\n");
            break;
        }

        examine_memory(addr);
        break;
    }
    case CMD_PRINT:
        print_expression(cmd.arg ? cmd.arg : "");
        break;
    case CMD_SET:
        set_command(cmd.arg ? cmd.arg : "");
        break;
    case CMD_HELP:
        show_help();
        break;
    case CMD_QUIT:
        exit(0);
        break;
    default:
        printf("unknown command\n");
        break;
    }

    cmd_free(&cmd);
}
static void sigint_handler(int sig)
{
    (void)sig;
    if (dbg.running && dbg.pid > 0)
        kill(dbg.pid, SIGINT);
}

void repl()
{
    char line[256];

    while (1) {

        printf("(tdb) ");

        if (!fgets(line,
                   sizeof(line),
                   stdin))
            break;

        handle(line);
    }
}

int main()
{
    signal(SIGINT, sigint_handler);
    repl();
    return 0;
}
