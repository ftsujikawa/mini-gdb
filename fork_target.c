/*
 * Test program for mini-gdb fork() child process support (threads /
 * lock / unlock / per-process breakpoints, watchpoints, regs).
 *
 * Parent forks 3 child processes that each call the same function.
 * Unlike thread_target.c's threads, each fork()ed child gets its OWN
 * copy-on-write copy of `shared_total` - the parent's own copy never
 * changes, and the children's changes are never visible to each other
 * or to the parent. None of the children exec() a different program,
 * so they keep running this same executable.
 *
 * Usage:
 *   make fork_target
 *   ./tdb
 *   (tdb) run fork_target
 *   (tdb) b worker
 *   (tdb) c                  # first child hits the breakpoint
 *   (tdb) threads             # lists parent + child processes (Pid column)
 *   (tdb) tb                  # backtrace of the stopped process/thread
 *   (tdb) regs
 *   (tdb) c                  # continue to the next child's hit
 *   (tdb) del 1               # remove the breakpoint
 *   (tdb) watch shared_total
 *   (tdb) c                  # stops when a child's own copy changes
 *   (tdb) c                  # repeat until all children have contributed
 *   (tdb) c                  # let it run to completion
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#define NUM_CHILDREN 3

int shared_total = 0;

void worker(int id)
{
    int contribution = (id + 1) * 10;

    usleep(id * 50000); /* stagger arrival so hits don't all collide */

    shared_total += contribution;

    printf("child %d (pid=%d) contributed %d, shared_total=%d\n",
           id, getpid(), contribution, shared_total);
}

int main(void)
{
    pid_t children[NUM_CHILDREN];

    for (int i = 0; i < NUM_CHILDREN; i++) {
        pid_t pid = fork();

        if (pid == 0) {
            worker(i);
            _exit(0);
        }

        children[i] = pid;
    }

    for (int i = 0; i < NUM_CHILDREN; i++)
        waitpid(children[i], NULL, 0);

    printf("all children done, parent's own shared_total=%d\n",
           shared_total);
    return 0;
}
