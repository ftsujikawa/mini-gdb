#include "dbg.h"
#include "heap.h"

#include <inttypes.h>

#define MAX_HEAP_HOOKS 4
#define MAX_HEAP_ALLOCS 4096

typedef enum {
    HEAP_HOOK_MALLOC = 0,
    HEAP_HOOK_FREE,
    HEAP_HOOK_REALLOC,
    HEAP_HOOK_CALLOC,
} heap_hook_kind_t;

typedef struct {
    int armed;
    heap_hook_kind_t kind;
    unsigned long addr;
    long original_data;
} heap_hook_t;

typedef struct {
    unsigned long ptr;
    unsigned long size;
    int live;
    heap_hook_kind_t kind;
    unsigned long seq;
    unsigned long call_site;
} heap_alloc_t;

typedef enum {
    HEAP_IDLE = 0,
    HEAP_WAIT_RET,
} heap_wait_t;

static int heap_trace_on;
static heap_hook_t heap_hooks[MAX_HEAP_HOOKS];
static int heap_hook_count;

static heap_alloc_t heap_allocs[MAX_HEAP_ALLOCS];
static int heap_alloc_count;
static unsigned long heap_seq;

static finish_bp_t heap_finish_bp;
static heap_wait_t heap_wait;
static heap_hook_kind_t heap_wait_kind;
static unsigned long heap_wait_size;
static unsigned long heap_wait_old;
static unsigned long heap_wait_site;

static const char *heap_hook_names[] = {
    "malloc",
    "free",
    "realloc",
    "calloc",
};

static unsigned long lookup_heap_addr(const char *name)
{
    unsigned long addr;
    const symbol_t *sym = lookup_symbol_entry(name);

    if (sym)
        return to_runtime_addr(sym->addr);

    if (lookup_plt_symbol(name, &addr) == 0)
        return to_runtime_addr(addr);

    char plt_name[280];

    snprintf(plt_name, sizeof(plt_name), "%s@plt", name);
    sym = lookup_symbol_entry(plt_name);

    if (sym)
        return to_runtime_addr(sym->addr);

    return 0;
}

static heap_hook_t *find_heap_hook(unsigned long bp_addr)
{
    for (int i = 0; i < heap_hook_count; i++) {
        if (heap_hooks[i].armed && heap_hooks[i].addr == bp_addr)
            return &heap_hooks[i];
    }

    return NULL;
}

static int poke_byte(unsigned long addr, long word, unsigned char byte)
{
    long patched = (word & ~0xff) | (unsigned long)byte;

    if (!dbg.running)
        return -1;

    if (ptrace(PTRACE_POKEDATA, dbg.pid, (void *)addr, (void *)patched) == -1) {
        if (errno != ESRCH)
            perror("ptrace poke");
        return -1;
    }

    return 0;
}

static int enable_heap_hook(heap_hook_t *hook)
{
    return poke_byte(hook->addr, hook->original_data, 0xcc);
}

static int restore_heap_hook(heap_hook_t *hook)
{
    return poke_byte(hook->addr, hook->original_data,
                     (unsigned char)(hook->original_data & 0xff));
}

static int step_over_heap_hook(heap_hook_t *hook)
{
    if (restore_heap_hook(hook) != 0)
        return -1;

    rewind_rip(hook->addr);

    if (ptrace(PTRACE_SINGLESTEP, dbg.pid, 0, 0) == -1) {
        perror("ptrace singlestep");
        return -1;
    }

    int status;

    if (waitpid(dbg.pid, &status, 0) < 0) {
        perror("waitpid");
        return -1;
    }

    if (WIFEXITED(status)) {
        dbg.running = 0;
        return -1;
    }

    return enable_heap_hook(hook);
}

static int arm_heap_finish(unsigned long ret_addr)
{
    breakpoint_t *existing = find_breakpoint(ret_addr);

    heap_finish_bp.active = 1;
    heap_finish_bp.addr = ret_addr;

    if (existing) {
        heap_finish_bp.uses_existing = 1;
        heap_finish_bp.original_data = 0;
        return 0;
    }

    long data = read_memory(ret_addr);

    if (data == -1) {
        heap_finish_bp.active = 0;
        return -1;
    }

    heap_finish_bp.uses_existing = 0;
    heap_finish_bp.original_data = data;

    long patched = (data & ~0xff) | 0xcc;

    if (ptrace(PTRACE_POKEDATA, dbg.pid, (void *)ret_addr,
               (void *)patched) == -1) {
        perror("ptrace poke");
        heap_finish_bp.active = 0;
        return -1;
    }

    return 0;
}

static void disarm_heap_finish(void)
{
    if (!heap_finish_bp.active)
        return;

    if (dbg.running && !heap_finish_bp.uses_existing) {
        ptrace(PTRACE_POKEDATA, dbg.pid, (void *)heap_finish_bp.addr,
               (void *)heap_finish_bp.original_data);
    }

    heap_finish_bp.active = 0;
}

static int heap_add_candidate(unsigned long addr,
                              unsigned long *addrs, int *count, int max)
{
    if (!addr || *count >= max)
        return 0;

    for (int i = 0; i < *count; i++) {
        if (addrs[i] == addr)
            return 0;
    }

    addrs[(*count)++] = addr;
    return 1;
}

static unsigned long heap_find_call_site(struct user_regs_struct *regs)
{
    const char *file;
    int line;
    unsigned long addrs[128];
    int count = 0;

    heap_add_candidate(regs->rip, addrs, &count, 128);

    unsigned long rbp = regs->rbp;

    for (int frame = 1; frame < 32 && rbp != 0; frame++) {
        unsigned long next_rbp;
        unsigned long ret_addr;

        if (peek_word(rbp, &next_rbp) != 0 ||
            peek_word(rbp + 8, &ret_addr) != 0)
            break;

        if (ret_addr == 0)
            break;

        heap_add_candidate(ret_addr, addrs, &count, 128);

        if (next_rbp <= rbp)
            break;

        rbp = next_rbp;
    }

    unsigned long sp = regs->rsp;

    for (int i = 0; i < 64; i++) {
        unsigned long word;

        if (peek_word(sp + (unsigned long)i * 8, &word) != 0)
            break;

        heap_add_candidate(word, addrs, &count, 128);
    }

    for (int i = 1; i < count; i++) {
        if (lookup_line(addrs[i], &file, &line) == 0)
            return addrs[i];
    }

    for (int i = 0; i < count; i++) {
        if (lookup_line(addrs[i], &file, &line) == 0)
            return addrs[i];
    }

    return 0;
}

static void heap_record_alloc(unsigned long ptr, unsigned long size,
                              heap_hook_kind_t kind,
                              unsigned long call_site)
{
    if (!ptr)
        return;

    for (int i = 0; i < heap_alloc_count; i++) {
        if (heap_allocs[i].ptr == ptr) {
            heap_allocs[i].live = 1;
            heap_allocs[i].size = size;
            heap_allocs[i].kind = kind;
            heap_allocs[i].seq = ++heap_seq;
            heap_allocs[i].call_site = call_site;
            return;
        }
    }

    if (heap_alloc_count >= MAX_HEAP_ALLOCS)
        return;

    heap_allocs[heap_alloc_count].ptr = ptr;
    heap_allocs[heap_alloc_count].size = size;
    heap_allocs[heap_alloc_count].live = 1;
    heap_allocs[heap_alloc_count].kind = kind;
    heap_allocs[heap_alloc_count].seq = ++heap_seq;
    heap_allocs[heap_alloc_count].call_site = call_site;
    heap_alloc_count++;
}

static void heap_record_free(unsigned long ptr)
{
    if (!ptr)
        return;

    for (int i = heap_alloc_count - 1; i >= 0; i--) {
        if (heap_allocs[i].live && heap_allocs[i].ptr == ptr) {
            heap_allocs[i].live = 0;
            return;
        }
    }
}

static int heap_get_return_address(unsigned long *ret_addr)
{
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, dbg.pid, 0, &regs);

    unsigned long from_rsp;

    if (peek_word(regs.rsp, &from_rsp) != 0)
        return -1;

    *ret_addr = from_rsp;
    return 0;
}

void heap_reset(void)
{
    heap_hook_count = 0;
    heap_alloc_count = 0;
    heap_seq = 0;
    heap_wait = HEAP_IDLE;
    heap_finish_bp.active = 0;
}

void heap_on_process_exit(void)
{
    if (!heap_trace_on)
        return;

    int leaks = 0;

    for (int i = 0; i < heap_alloc_count; i++) {
        if (heap_allocs[i].live)
            leaks++;
    }

    if (leaks > 0)
        printf("[heap] %d leak(s) at process exit\n", leaks);
    else
        printf("[heap] no leaks detected\n");
}

int heap_trace_enabled(void)
{
    return heap_trace_on;
}

void heap_set_trace(int on)
{
    heap_trace_on = on ? 1 : 0;

    if (!dbg.running) {
        if (heap_trace_on)
            printf("Heap tracing enabled (will arm on run)\n");
        else
            printf("Heap tracing disabled\n");
        return;
    }

    if (heap_trace_on) {
        if (heap_arm_hooks() == 0)
            printf("Heap tracing enabled\n");
    } else {
        heap_disarm_hooks();
        printf("Heap tracing disabled\n");
    }
}

int heap_arm_hooks(void)
{
    if (!dbg.running) {
        printf("no process\n");
        return -1;
    }

    heap_disarm_hooks();

    for (int i = 0; i < (int)(sizeof(heap_hook_names) / sizeof(heap_hook_names[0])); i++) {
        unsigned long addr = lookup_heap_addr(heap_hook_names[i]);

        if (!addr)
            continue;

        long data = read_memory(addr);

        if (data == -1)
            continue;

        if (heap_hook_count >= MAX_HEAP_HOOKS)
            break;

        heap_hook_t *hook = &heap_hooks[heap_hook_count++];

        hook->kind = (heap_hook_kind_t)i;
        hook->addr = addr;
        hook->original_data = data;
        hook->armed = 1;

        if (poke_byte(addr, data, 0xcc) != 0) {
            hook->armed = 0;
            heap_hook_count--;
            continue;
        }
    }

    if (heap_hook_count == 0) {
        printf("no heap symbols found (malloc/free/realloc/calloc)\n");
        return -1;
    }

    printf("[heap] armed %d hook(s)\n", heap_hook_count);
    return 0;
}

void heap_disarm_hooks(void)
{
    disarm_heap_finish();
    heap_wait = HEAP_IDLE;

    for (int i = 0; i < heap_hook_count; i++) {
        heap_hook_t *hook = &heap_hooks[i];

        if (!hook->armed)
            continue;

        restore_heap_hook(hook);
        hook->armed = 0;
    }

    heap_hook_count = 0;
}

int heap_pending_finish(void)
{
    return heap_wait == HEAP_WAIT_RET && heap_finish_bp.active;
}

static int heap_begin_wait(struct user_regs_struct *regs,
                           heap_hook_kind_t kind,
                           unsigned long size,
                           unsigned long old_ptr)
{
    unsigned long ret_addr;

    if (heap_get_return_address(&ret_addr) != 0)
        return -1;

    if (arm_heap_finish(ret_addr) != 0)
        return -1;

    heap_wait = HEAP_WAIT_RET;
    heap_wait_kind = kind;
    heap_wait_size = size;
    heap_wait_old = old_ptr;
    heap_wait_site = heap_find_call_site(regs);
    return 0;
}

int heap_handle_trap(struct user_regs_struct *regs)
{
    if (!heap_trace_on || heap_wait != HEAP_IDLE)
        return 0;

    heap_hook_t *hook = find_heap_hook(regs->rip - 1);

    if (!hook)
        return 0;

    switch (hook->kind) {
    case HEAP_HOOK_MALLOC:
        if (heap_begin_wait(regs, HEAP_HOOK_MALLOC, regs->rdi, 0) != 0)
            return 0;
        break;

    case HEAP_HOOK_CALLOC: {
        unsigned long nmemb = regs->rdi;
        unsigned long size = regs->rsi;
        unsigned long total = nmemb * size;

        if (heap_begin_wait(regs, HEAP_HOOK_CALLOC, total, 0) != 0)
            return 0;
        break;
    }

    case HEAP_HOOK_REALLOC:
        if (heap_begin_wait(regs, HEAP_HOOK_REALLOC, regs->rsi, regs->rdi) != 0)
            return 0;
        break;

    case HEAP_HOOK_FREE:
        heap_record_free(regs->rdi);
        break;
    }

    if (step_over_heap_hook(hook) != 0)
        return 0;

    return 1;
}

int heap_handle_finish_trap(struct user_regs_struct *regs)
{
    if (heap_wait != HEAP_WAIT_RET ||
        !heap_finish_bp.active ||
        regs->rip - 1 != heap_finish_bp.addr)
        return 0;

    unsigned long ret_ptr = regs->rax;

    if (!heap_finish_bp.uses_existing && dbg.running) {
        ptrace(PTRACE_POKEDATA, dbg.pid, (void *)heap_finish_bp.addr,
               (void *)heap_finish_bp.original_data);
    }

    rewind_rip(heap_finish_bp.addr);
    heap_finish_bp.active = 0;
    heap_wait = HEAP_IDLE;

    switch (heap_wait_kind) {
    case HEAP_HOOK_MALLOC:
    case HEAP_HOOK_CALLOC:
        heap_record_alloc(ret_ptr, heap_wait_size, heap_wait_kind,
                          heap_wait_site);
        break;

    case HEAP_HOOK_REALLOC:
        if (heap_wait_old && heap_wait_old != ret_ptr)
            heap_record_free(heap_wait_old);
        heap_record_alloc(ret_ptr, heap_wait_size, HEAP_HOOK_REALLOC,
                          heap_wait_site);
        break;

    default:
        break;
    }

    return 1;
}

static const char *heap_kind_name(heap_hook_kind_t kind)
{
    switch (kind) {
    case HEAP_HOOK_MALLOC:  return "malloc";
    case HEAP_HOOK_FREE:    return "free";
    case HEAP_HOOK_REALLOC: return "realloc";
    case HEAP_HOOK_CALLOC:  return "calloc";
    default:                return "?";
    }
}

static void show_heap_entries(int leaks_only)
{
    int shown = 0;

    for (int i = 0; i < heap_alloc_count; i++) {
        if (!heap_allocs[i].live)
            continue;

        printf("#%-4lu  0x%-16lx %8lu bytes  (%s)",
               heap_allocs[i].seq,
               heap_allocs[i].ptr,
               heap_allocs[i].size,
               heap_kind_name(heap_allocs[i].kind));

        if (heap_allocs[i].call_site) {
            const char *file;
            int line;

            if (lookup_line(heap_allocs[i].call_site, &file, &line) == 0)
                printf("  at %s:%d", file, line);
        }

        printf("\n");
        shown++;
    }

    if (shown == 0) {
        if (leaks_only)
            printf("no leaks\n");
        else
            printf("no live heap allocations\n");
        return;
    }

    if (leaks_only)
        printf("%d leak(s)\n", shown);
    else
        printf("%d live allocation(s)\n", shown);
}

void show_heap(void)
{
    if (!heap_trace_on) {
        printf("heap tracing is off (use: set heap-trace on)\n");
        return;
    }

    if (heap_alloc_count == 0) {
        printf("no heap records yet\n");
        return;
    }

    printf("Live heap allocations:\n");
    show_heap_entries(0);
}

void show_leaks(void)
{
    if (!heap_trace_on) {
        printf("heap tracing is off (use: set heap-trace on)\n");
        return;
    }

    printf("Potential leaks (live allocations):\n");
    show_heap_entries(1);
}
