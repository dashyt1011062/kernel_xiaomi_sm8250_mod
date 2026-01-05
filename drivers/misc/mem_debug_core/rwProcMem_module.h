#ifndef RWPROCMEM_H_
#define RWPROCMEM_H_
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/atomic.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/version.h>

#include "api_proxy.h"
#include "phy_mem.h"
#include "proc_maps.h"
#include "proc_list.h"
#include "proc_root.h"
#include "proc_rss.h"
#include "proc_cmdline.h"
#include "ver_control.h"
#include "test.h"
#include "rwpm_ioctl.h"
//////////////////////////////////////////////////////////////////

enum {
	CMD_INIT_DEVICE_INFO = 1, 		// 初始化设备信息
	CMD_OPEN_PROCESS, 				// 打开进程
	CMD_READ_PROCESS_MEMORY,       	// 读取进程内存
    CMD_WRITE_PROCESS_MEMORY,      	// 写入进程内存
	CMD_CLOSE_PROCESS, 				// 关闭进程
	CMD_GET_PROCESS_MAPS_COUNT, 	// 获取进程的内存块地址数量
	CMD_GET_PROCESS_MAPS_LIST, 		// 获取进程的内存块地址列表
	CMD_CHECK_PROCESS_ADDR_PHY,		// 检查进程内存是否有物理内存位置
	CMD_GET_PID_LIST,				// 获取进程PID列表
	CMD_SET_PROCESS_ROOT,			// 提升进程权限到Root
	CMD_GET_PROCESS_RSS,			// 获取进程的物理内存占用大小
	CMD_GET_PROCESS_CMDLINE_ADDR,	// 获取进程cmdline的内存地址
	CMD_HIDE_KERNEL_MODULE,			// 隐藏驱动
};

int hwbp_init(void);
void hwbp_exit(void);
ssize_t hwbp_dispatch(struct ioctl_request *hdr, char __user* buf);
int hwbp_release(struct inode *inode, struct file *filp);

#endif /* RWPROCMEM_H_ */
