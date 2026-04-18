/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __ASM_ARM64_UAPI_PERF_EVENT_H
#define __ASM_ARM64_UAPI_PERF_EVENT_H

#include <linux/types.h>

#define PERF_ARM64_BP_RAW_MAGIC		0x42504650
#define PERF_ARM64_BP_RAW_VERSION	1

#define PERF_ARM64_BP_RAW_F_VALID	(1ULL << 0)
#define PERF_ARM64_BP_RAW_F_USER	(1ULL << 1)

struct perf_arm64_bp_raw_sample {
	__u32	magic;
	__u16	version;
	__u16	size;
	__u64	flags;
	__u64	trigger;
	__u32	s[32];
	__u32	fpsr;
	__u32	fpcr;
};

#endif /* __ASM_ARM64_UAPI_PERF_EVENT_H */
