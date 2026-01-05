#ifndef _UAPI_LINUX_MEM_DEBUG_CORE_H_
#define _UAPI_LINUX_MEM_DEBUG_CORE_H_

#include <linux/types.h>
#include <linux/ioctl.h>

struct mem_debug_ioctl {
	__u64 user_buf;
	__u64 size;
};

#define MEM_DEBUG_IOC_MAGIC  'M'
#define MEM_DEBUG_IOC_DISPATCH _IOWR(MEM_DEBUG_IOC_MAGIC, 0x01, struct mem_debug_ioctl)

#endif /* _UAPI_LINUX_MEM_DEBUG_CORE_H_ */
