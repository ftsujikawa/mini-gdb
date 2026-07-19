/*
 * Test program for mini-gdb thread support (threads / thread <num> /
 * per-thread breakpoints, watchpoints, regs, backtrace).
 *
 * Spawns 3 worker threads that each call the same function and write to
 * a shared global, so a single breakpoint/watchpoint can be observed
 * hitting from multiple threads.
 *
 * Usage:
 *   make thread_target
 *   ./tdb
 *   (tdb) run thread_target
 *   (tdb) b worker
 *   (tdb) c                  # first worker thread hits the breakpoint
 *   (tdb) threads             # lists main + worker threads created so far
 *   (tdb) tb                  # backtrace of the stopped thread
 *   (tdb) regs
 *   (tdb) c                  # continue to the next worker's hit
 *   (tdb) thread 1            # switch focus to another thread
 *   (tdb) del 1               # remove the breakpoint
 *   (tdb) watch shared_total
 *   (tdb) c                  # stops when shared_total actually changes
 *   (tdb) c                  # repeat until all workers have contributed
 *   (tdb) c                  # let it run to completion
 */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#define NUM_WORKERS 3

int shared_total = 0;

void *worker(void *arg)
{
    int id = *(int *)arg;
    int contribution = (id + 1) * 10;

    usleep(id * 50000); /* stagger arrival so hits don't all collide */

    shared_total += contribution;

    printf("worker %d contributed %d, shared_total=%d\n",
           id, contribution, shared_total);

    return NULL;
}

int main(void)
{
    pthread_t workers[NUM_WORKERS];
    int ids[NUM_WORKERS];

    for (int i = 0; i < NUM_WORKERS; i++) {
        ids[i] = i;
        pthread_create(&workers[i], NULL, worker, &ids[i]);
    }

    for (int i = 0; i < NUM_WORKERS; i++)
        pthread_join(workers[i], NULL);

    printf("all workers done, shared_total=%d\n", shared_total);
    return 0;
}
