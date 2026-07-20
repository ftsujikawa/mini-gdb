#include "dbg.h"

int read_target_byte(unsigned long addr, unsigned char *out)
{
    unsigned long aligned = addr & ~(unsigned long)(sizeof(long) - 1);
    long word = read_memory(aligned);

    if (word == -1)
        return -1;

    *out = (unsigned char)(word >> (8 * (addr - aligned)));
    return 0;
}
int poke_word(unsigned long addr, unsigned long value)
{
    errno = 0;

    if (ptrace(PTRACE_POKEDATA, dbg.current_tid, (void *)addr,
               (void *)value) == -1) {
        perror("ptrace poke");
        return -1;
    }

    return 0;
}
/* All threads of the SAME process share one address space, so any of
 * its currently ptrace-stopped tids works equally well for a PEEKDATA;
 * callers that already know a specific stopped tid belonging to a
 * *different* process than dbg.current_tid (e.g. continue_execution's
 * event dispatch, where the selected thread may still be running) must
 * use this instead of read_memory(), which always targets whichever
 * process dbg.current_tid currently belongs to. */
long read_memory_tid(pid_t tid, unsigned long addr)
{
    errno = 0;

    long data =
        ptrace(
            PTRACE_PEEKDATA,
            tid,
            (void*)addr,
            0
        );

    if (errno != 0) {
        perror("ptrace peek");
        return -1;
    }

    return data;
}

long read_memory(unsigned long addr)
{
    return read_memory_tid(dbg.current_tid, addr);
}

int peek_word(unsigned long addr, unsigned long *value)
{
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA,
                       dbg.current_tid,
                       (void *)addr,
                       0);

    if (errno != 0)
        return -1;

    *value = (unsigned long)data;
    return 0;
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
