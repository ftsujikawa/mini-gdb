#ifndef HEAP_H
#define HEAP_H

#include <sys/user.h>

void heap_reset(void);
void heap_on_process_exit(void);

int heap_trace_enabled(void);
void heap_set_trace(int on);

int heap_arm_hooks(void);
void heap_disarm_hooks(void);

/* Returns 1 if the trap was handled and execution should continue. */
int heap_handle_trap(struct user_regs_struct *regs);

/* Returns 1 if a pending alloc hook finish was handled. */
int heap_handle_finish_trap(struct user_regs_struct *regs);

int heap_pending_finish(void);

void show_heap(void);
void show_leaks(void);

#endif
