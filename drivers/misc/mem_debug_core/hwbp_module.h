#ifndef HWBP_MODULE_H_
#define HWBP_MODULE_H_
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/compat.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/ksm.h>
#include <linux/mutex.h>
#include <linux/rwlock.h>
#include <linux/ktime.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include "ver_control.h"
#include "arm64_register_helper.h"
#include "cvector.h"
#include "rwpm_ioctl.h"
//////////////////////////////////////////////////////////////////

enum {
	CMD_HWBP_BASE = 0x40,
	CMD_HWBP_OPEN_PROCESS = CMD_HWBP_BASE, 	// 打开进程
	CMD_HWBP_CLOSE_PROCESS, 				// 关闭进程
	CMD_HWBP_READ_PROCESS_MEM, 			// 读取进程内存
	CMD_HWBP_WRITE_PROCESS_MEM,			// 写入进程内存
	CMD_HWBP_READ_USER_INSN,				// 读取进程指令
	CMD_HWBP_GET_NUM_BRPS, 				// 获取CPU硬件执行断点支持数量
	CMD_HWBP_GET_NUM_WRPS, 				// 获取CPU硬件访问断点支持数量
	CMD_HWBP_INST_PROCESS_HWBP,			// 安装进程硬件断点
	CMD_HWBP_UNINST_PROCESS_HWBP,		// 卸载进程硬件断点
	CMD_HWBP_SUSPEND_PROCESS_HWBP,		// 暂停进程硬件断点
	CMD_HWBP_RESUME_PROCESS_HWBP,		// 恢复进程硬件断点
	CMD_HWBP_GET_HWBP_HIT_COUNT,			// 获取硬件断点命中地址数量
	CMD_HWBP_GET_HWBP_HIT_DETAIL,			// 获取硬件断点命中详细信息
	CMD_HWBP_CLEAR_HWBP_HIT,				// 清空硬件断点命中缓存
	CMD_HWBP_SET_HOOK_PC,					// 设置无条件Hook跳转
	CMD_HWBP_HIDE_KERNEL_MODULE,			// 隐藏驱动
	CMD_HWBP_SET_TRACE_STEP_COUNT = 0x53,	// 设置追踪步数
	CMD_HWBP_SET_STEP_SIMULATE,			// 指令模拟步进
	CMD_HWBP_SET_STEP_FILTER,				// 设置步进指令过滤模式
	CMD_HWBP_GET_STEP_LOG = 0x58,			// 获取模拟步进日志
	CMD_HWBP_THREAD_SNAPSHOT = 0x59,		// 冻结线程并抓取寄存器+栈快照
	CMD_HWBP_SET_TRACERPID_HIDE = 0x5A,		// 设置要隐藏 TracerPid 的 pid (tgid)，0 关闭（兼容）
	CMD_HWBP_TRACERPID_ADD_TID = 0x5B,		// 添加需要伪装的 tid
	CMD_HWBP_TRACERPID_DEL_TID = 0x5C,		// 移除需要伪装的 tid
	CMD_HWBP_TRACERPID_CLEAR = 0x5D,		// 清空伪装 tid 列表
	CMD_HWBP_GET_DRIVER_LOG = 0x5E,			// 读取驱动日志
	CMD_HWBP_CLEAR_DRIVER_LOG = 0x5F,		// 清空驱动日志
	CMD_HWBP_START_STEP_SESSION = 0x60,		// 启动模拟步进会话
	CMD_HWBP_GET_STEP_STATUS = 0x61,		// 获取模拟步进状态
};

int hwbp_init(void);
void hwbp_exit(void);
ssize_t hwbp_dispatch(struct ioctl_request *hdr, char __user* buf);
int hwbp_release(struct inode *inode, struct file *filp);

#pragma pack(1)
struct my_user_pt_regs {
	uint64_t regs[31];
	uint64_t sp;
	uint64_t pc;
	uint64_t pstate;
	uint64_t orig_x0;
	uint64_t syscallno;
};
struct HWBP_HIT_ITEM {
	uint64_t task_id;
	uint64_t hit_addr;
	uint64_t hit_time;
	struct my_user_pt_regs regs_info;
};
#pragma pack()

enum {
	STEP_FILTER_ALL = 0,			// 记录所有指令
	STEP_FILTER_BRANCH_ONLY = 1,	// 仅记录跳转/分支类指令
};

enum {
	STEP_STOP_NONE = 0,
	STEP_STOP_COUNT_REACHED = 1,
	STEP_STOP_BUFFER_FULL = 2,
	STEP_STOP_READ_INSN_FAILED = 3,
	STEP_STOP_NEXT_PC_INVALID = 4,
	STEP_STOP_BP_RESTORE_FAILED = 5,
	STEP_STOP_MANUAL = 6,
};

#pragma pack(1)
struct STEP_LOG_ITEM {
	uint64_t task_id;
	uint64_t pc;
	uint64_t next_pc;
	uint32_t insn;
	uint32_t flags;		// bit0: 是分支指令
	uint64_t seq;		// 单调递增序号
};

struct STEP_SESSION_STATUS {
	uint32_t running;
	uint32_t done;
	uint32_t stop_reason;
	uint32_t reserved;
	uint64_t requested_steps;
	uint64_t logged_steps;
	uint64_t tracked_tid;
	uint64_t next_seq;
};
#pragma pack()
struct HWBP_HANDLE_INFO {
	uint64_t task_id;
	struct task_struct *task;
	struct perf_event * sample_hbp;
	struct perf_event_attr original_attr;
	struct perf_event_attr sim_next_attr;
	bool sim_next_active;
	bool is_32bit_task;
#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
	struct perf_event_attr next_instruction_attr;
#endif
	struct mutex hit_lock;
	bool step_pending;
	bool step_exhausted;
	bool bp_restore_pending;
	size_t step_remaining;
	size_t hit_total_count;
	cvector hit_item_arr;
};

#endif /* HWBP_MODULE_H_ */
