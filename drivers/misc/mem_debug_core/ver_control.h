#ifndef VERSION_CONTROL_H_
#define VERSION_CONTROL_H_
#include <linux/version.h>

// Built-in driver integration
#define CONFIG_MODULE_GUIDE_ENTRY

// Disable procfs IPC
#undef CONFIG_USE_PROC_FILE_NODE

// Disable debug printk in production
#undef CONFIG_DEBUG_PRINTK

// Disable kallsyms lookup (use exported symbols)
#undef CONFIG_KALLSYMS_LOOKUP_NAME

// Enable hit-next mode for simulate-step
#define CONFIG_MODIFY_HIT_NEXT_MODE

// Trace defaults
#define CONFIG_TRACE_MAX_SIZE 65536
#define CONFIG_TRACE_DEFAULT_SIZE 1024
#define CONFIG_TRACE_MAX_STEP 1024
#define CONFIG_TRACE_DEFAULT_STEP 64

// Anti-ptrace detection mode (optional)
#define CONFIG_ANTI_PTRACE_DETECTION_MODE

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif
#ifndef MY_LINUX_VERSION_CODE
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0))
#define MY_LINUX_VERSION_CODE KERNEL_VERSION(4,19,113)
#else
#define MY_LINUX_VERSION_CODE LINUX_VERSION_CODE
#endif
#endif

#ifdef CONFIG_DEBUG_PRINTK
#define printk_debug printk
#else
static inline void printk_debug(char *fmt, ...) {}
#endif

#endif /* VERSION_CONTROL_H_ */
