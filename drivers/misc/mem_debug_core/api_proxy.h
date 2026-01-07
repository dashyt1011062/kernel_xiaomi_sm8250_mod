#ifndef API_PROXY_H_
#define API_PROXY_H_

#include "ver_control.h"
#include "linux_kernel_api.h"
#include <linux/compiler.h>
#include <linux/ctype.h>
#include <asm/uaccess.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/hw_breakpoint.h>

static __maybe_unused struct perf_event* x_register_user_hw_breakpoint(struct perf_event_attr *attr, perf_overflow_handler_t triggered, void *context, struct task_struct *tsk) {
	return register_user_hw_breakpoint(attr, triggered, context, tsk);
}

static __maybe_unused void x_unregister_hw_breakpoint(struct perf_event *bp) {
	unregister_hw_breakpoint(bp);
}

static __maybe_unused int x_modify_user_hw_breakpoint(struct perf_event *bp, struct perf_event_attr *attr) {
	return modify_user_hw_breakpoint(bp, attr);
}

static inline bool x_isdigit(char c) { return (unsigned)(c - '0') < 10; }
static inline int x_atoi(const char arr[]) {
	int index = 0;
	int flag = 1;
	int num = 0;

	if (arr == NULL) { return -1; }
	while (isspace(arr[index])) { index++; }
	if (arr[index] == '-') { flag = -1; }
	if (arr[index] == '-' || arr[index] == '+') { index++; }
	while (arr[index] >= '0' && arr[index] <= '9') { num = num * 10 + arr[index] - '0';	index++; }
	return flag * num;
}

static __maybe_unused struct task_struct *x_get_current(void) {
	unsigned long sp_el0;
	asm ("mrs %0, sp_el0" : "=r" (sp_el0));
	return (struct task_struct *)sp_el0;
}

static __maybe_unused void * x_kmalloc(size_t size, gfp_t flags) {
	return __kmalloc(size, flags);
}

static __maybe_unused unsigned long x_copy_from_user(void *to, const void __user *from, unsigned long n) {
	return __arch_copy_from_user(to, from, n);
}

static __maybe_unused unsigned long x_copy_to_user(void __user *to, const void *from, unsigned long n) {
	return __arch_copy_to_user(to, from, n);
}
#endif /* API_PROXY_H_ */
