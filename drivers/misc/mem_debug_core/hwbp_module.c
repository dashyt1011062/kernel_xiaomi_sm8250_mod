#include "hwbp_module.h"
#include "proc_pid.h"
#include "api_proxy.h"
#include "anti_ptrace_detection.h"
#include "rwpm_ioctl.h"
#include <asm/debug-monitors.h>
#include <asm/sysreg.h>

/* 强制禁用 CPU 单步路径，统一使用“修改下一指令地址”模拟步进 */
#undef CONFIG_USE_SINGLE_STEP_MODE

extern ssize_t rwpm_force_read_task(struct task_struct *task, size_t addr, void *dst, size_t size);
//////////////////////////////////////////////////////////////////

static atomic64_t g_hook_pc;


static struct mutex g_hwbp_handle_info_mutex;
static cvector g_hwbp_handle_info_arr = NULL;
#ifdef CONFIG_USE_SINGLE_STEP_MODE
static struct step_hook g_step_hook;
static bool g_step_hook_installed = false;
#endif

static bool g_trace_enabled = false;
static int g_trace_mode = TRACE_MODE_PC;
static size_t g_trace_capacity = CONFIG_TRACE_DEFAULT_SIZE;
static size_t g_trace_step_count = CONFIG_TRACE_DEFAULT_STEP;
static DEFINE_SPINLOCK(g_step_log_lock);
#define STEP_LOG_CAPACITY 1024
static struct STEP_LOG_ITEM g_step_log[STEP_LOG_CAPACITY];
static size_t g_step_log_head;
static size_t g_step_log_count;

static __maybe_unused void step_log_push(uint64_t tid, uint64_t pc, uint32_t insn, uint64_t next_pc)
{
	unsigned long flags;
	spin_lock_irqsave(&g_step_log_lock, flags);
	g_step_log[g_step_log_head].task_id = tid;
	g_step_log[g_step_log_head].pc = pc;
	g_step_log[g_step_log_head].next_pc = next_pc;
	g_step_log[g_step_log_head].insn = insn;
	g_step_log[g_step_log_head].reserved = 0;
	g_step_log_head = (g_step_log_head + 1) % STEP_LOG_CAPACITY;
	if (g_step_log_count < STEP_LOG_CAPACITY)
		g_step_log_count++;
	spin_unlock_irqrestore(&g_step_log_lock, flags);
}
static bool g_simulate_step_enabled = false;
static const size_t g_read_mem_max = 4096;

static inline s64 sign_extend_64(u64 val, int bits) {
    u64 shift = 64 - (u64)bits;
    return (s64)((val << shift)) >> shift;
}

static inline bool aarch64_cond_passed(u32 cond, u64 pstate) {
    int N = (pstate >> 31) & 1;
    int Z = (pstate >> 30) & 1;
    int C = (pstate >> 29) & 1;
    int V = (pstate >> 28) & 1;
    switch (cond & 0xf) {
    case 0x0: return Z == 1;                // EQ
    case 0x1: return Z == 0;                // NE
    case 0x2: return C == 1;                // CS/HS
    case 0x3: return C == 0;                // CC/LO
    case 0x4: return N == 1;                // MI
    case 0x5: return N == 0;                // PL
    case 0x6: return V == 1;                // VS
    case 0x7: return V == 0;                // VC
    case 0x8: return C == 1 && Z == 0;      // HI
    case 0x9: return C == 0 || Z == 1;      // LS
    case 0xa: return N == V;                // GE
    case 0xb: return N != V;                // LT
    case 0xc: return Z == 0 && N == V;      // GT
    case 0xd: return Z == 1 || N != V;      // LE
    case 0xe: return true;                  // AL
    default:  return false;                 // NV
    }
}

static __maybe_unused bool read_user_insn_task(struct task_struct *task, u64 pc, u32 *insn) {
    if (!task || !insn || !pc) return false;
    return rwpm_force_read_task(task, pc, insn, sizeof(*insn)) == sizeof(*insn);
}

static __maybe_unused u64 calc_next_pc(struct pt_regs *regs, u32 insn) {
    u64 pc = regs->pc;
    u64 next = pc + 4;

    if ((insn & 0x7C000000) == 0x14000000) { // B
        s64 imm = sign_extend_64((insn & 0x03ffffff) << 2, 28);
        return pc + imm;
    }
    if ((insn & 0x7C000000) == 0x94000000) { // BL
        s64 imm = sign_extend_64((insn & 0x03ffffff) << 2, 28);
        return pc + imm;
    }
    if ((insn & 0xFF000010) == 0x54000000) { // B.cond
        u32 cond = insn & 0xf;
        s64 imm = sign_extend_64(((insn >> 5) & 0x7ffff) << 2, 21);
        if (aarch64_cond_passed(cond, regs->pstate)) {
            return pc + imm;
        }
        return next;
    }
    if ((insn & 0x7F000000) == 0x34000000) { // CBZ
        u32 rt = insn & 0x1f;
        bool is64 = (insn >> 31) & 1;
        u64 val = is64 ? regs->regs[rt] : (u32)regs->regs[rt];
        s64 imm = sign_extend_64(((insn >> 5) & 0x7ffff) << 2, 21);
        if (val == 0) return pc + imm;
        return next;
    }
    if ((insn & 0x7F000000) == 0x35000000) { // CBNZ
        u32 rt = insn & 0x1f;
        bool is64 = (insn >> 31) & 1;
        u64 val = is64 ? regs->regs[rt] : (u32)regs->regs[rt];
        s64 imm = sign_extend_64(((insn >> 5) & 0x7ffff) << 2, 21);
        if (val != 0) return pc + imm;
        return next;
    }
    if ((insn & 0x7F000000) == 0x36000000 || (insn & 0x7F000000) == 0x37000000) { // TBZ/TBNZ
        bool tbnz = (insn & 0x01000000) != 0;
        u32 rt = insn & 0x1f;
        u32 b5 = (insn >> 31) & 1;
        u32 b40 = (insn >> 19) & 0x1f;
        u32 bit = (b5 << 5) | b40;
        u64 val = regs->regs[rt];
        bool bit_set = ((val >> bit) & 1) != 0;
        s64 imm = sign_extend_64(((insn >> 5) & 0x3fff) << 2, 16);
        if ((tbnz && bit_set) || (!tbnz && !bit_set)) {
            return pc + imm;
        }
        return next;
    }
    if ((insn & 0xFFFFFC1F) == 0xD61F0000) { // BR
        u32 rn = (insn >> 5) & 0x1f;
        return (rn == 31) ? regs->sp : regs->regs[rn];
    }
    if ((insn & 0xFFFFFC1F) == 0xD63F0000) { // BLR
        u32 rn = (insn >> 5) & 0x1f;
        return (rn == 31) ? regs->sp : regs->regs[rn];
    }
    if ((insn & 0xFFFFFC1F) == 0xD65F0000) { // RET
        u32 rn = (insn >> 5) & 0x1f;
        return (rn == 31) ? regs->sp : regs->regs[rn];
    }

    return next;
}

static void record_hit_details(struct HWBP_HANDLE_INFO *info, struct pt_regs *regs) {
    struct HWBP_HIT_ITEM hit_item = {0};
	if (!info || !regs) {
        return;
    }
	hit_item.task_id = info->task_id;
    hit_item.hit_addr = regs->pc;
	hit_item.hit_time = ktime_get_real_seconds();
    memcpy(&hit_item.regs_info.regs, regs->regs, sizeof(hit_item.regs_info.regs));
    hit_item.regs_info.sp = regs->sp;
    hit_item.regs_info.pc = regs->pc;
    hit_item.regs_info.pstate = regs->pstate;
    hit_item.regs_info.orig_x0 = regs->orig_x0;
    hit_item.regs_info.syscallno = regs->syscallno;
    if (info->hit_item_arr) {
		if(cvector_length(info->hit_item_arr) < MIN_LEN) { // 最多存放MIN_LEN个
			cvector_pushback(info->hit_item_arr, &hit_item);
		}
    }
}

static size_t trace_item_size(void) {
	return (g_trace_mode == TRACE_MODE_FULL) ? sizeof(struct TRACE_ITEM_FULL) : sizeof(struct TRACE_ITEM_PC);
}

static void trace_buffer_free(struct HWBP_HANDLE_INFO *info) {
	if (!info) return;
	if (info->trace_buf) {
		kfree(info->trace_buf);
		info->trace_buf = NULL;
	}
	info->trace_capacity = 0;
	info->trace_item_size = 0;
	info->trace_head = 0;
	info->trace_count = 0;
}

static int trace_buffer_alloc(struct HWBP_HANDLE_INFO *info) {
	size_t item_size;
	size_t cap;
	void *buf;
	if (!info) return -EINVAL;
	if (!g_trace_enabled) return 0;
	cap = g_trace_capacity;
	if (cap == 0) return -EINVAL;
	item_size = trace_item_size();
	buf = kmalloc(item_size * cap, GFP_KERNEL);
	if (!buf) return -ENOMEM;
	info->trace_buf = buf;
	info->trace_capacity = cap;
	info->trace_item_size = item_size;
	info->trace_head = 0;
	info->trace_count = 0;
	return 0;
}

static void trace_buffer_reset(struct HWBP_HANDLE_INFO *info) {
	trace_buffer_free(info);
	trace_buffer_alloc(info);
}

#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
static bool arm64_move_bp_to_next_instruction(struct perf_event *bp, uint64_t next_instruction_addr, struct perf_event_attr *original_attr, struct perf_event_attr * next_instruction_attr) {
    int result;
	if (!bp || !original_attr || !next_instruction_attr || !next_instruction_addr) {
        return false;
    }
	memcpy(next_instruction_attr, original_attr, sizeof(struct perf_event_attr));
	next_instruction_attr->bp_addr = next_instruction_addr;
	next_instruction_attr->bp_len = HW_BREAKPOINT_LEN_4;
	next_instruction_attr->bp_type = HW_BREAKPOINT_X;
	next_instruction_attr->disabled = 0;
	result = x_modify_user_hw_breakpoint(bp, next_instruction_attr);
	if(result) {
		next_instruction_attr->bp_addr = 0;
		return false;
	}
	return true;
}

static bool arm64_recovery_bp_to_original(struct perf_event *bp, struct perf_event_attr *original_attr, struct perf_event_attr * next_instruction_attr) {
    int result;
	if (!bp || !original_attr || !next_instruction_attr) {
        return false;
    }
	result = x_modify_user_hw_breakpoint(bp, original_attr);
	if(result) {
		return false;
	}
	next_instruction_attr->bp_addr = 0;
	return true;
}
#endif


static void hwbp_hit_user_info_callback(struct perf_event *bp,
	struct perf_sample_data *data,
	struct pt_regs *regs, struct HWBP_HANDLE_INFO * hwbp_handle_info) {
	hwbp_handle_info->hit_total_count++;
	record_hit_details(hwbp_handle_info, regs);
}

#ifdef CONFIG_USE_SINGLE_STEP_MODE
static int hwbp_step_hook(struct pt_regs *regs, unsigned int esr) {
	citerator iter;
	struct task_struct *task = current;
	int handled = DBG_HOOK_ERROR;
	if (!task) return DBG_HOOK_ERROR;

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if (!hwbp_handle_info->task || hwbp_handle_info->task_id != task_pid_nr(task)) {
			continue;
		}
		mutex_lock(&hwbp_handle_info->hit_lock);
		if (hwbp_handle_info->step_pending) {
			if (g_trace_enabled && hwbp_handle_info->trace_buf && hwbp_handle_info->trace_capacity) {
				size_t idx = hwbp_handle_info->trace_head;
				if (g_trace_mode == TRACE_MODE_FULL) {
					struct TRACE_ITEM_FULL *items = (struct TRACE_ITEM_FULL *)hwbp_handle_info->trace_buf;
					struct TRACE_ITEM_FULL *item = &items[idx];
					item->task_id = hwbp_handle_info->task_id;
					item->hit_time = ktime_get_real_seconds();
					memcpy(&item->regs_info.regs, regs->regs, sizeof(item->regs_info.regs));
					item->regs_info.sp = regs->sp;
					item->regs_info.pc = regs->pc;
					item->regs_info.pstate = regs->pstate;
					item->regs_info.orig_x0 = regs->orig_x0;
					item->regs_info.syscallno = regs->syscallno;
					item->esr = esr;
					item->far = read_sysreg(far_el1);
					item->insn = 0;
					rwpm_force_read_task(hwbp_handle_info->task, regs->pc, &item->insn, sizeof(item->insn));
				} else {
					struct TRACE_ITEM_PC *items = (struct TRACE_ITEM_PC *)hwbp_handle_info->trace_buf;
					struct TRACE_ITEM_PC *item = &items[idx];
					item->task_id = hwbp_handle_info->task_id;
					item->hit_time = ktime_get_real_seconds();
					item->pc = regs->pc;
					item->pstate = regs->pstate;
					item->esr = esr;
					item->far = read_sysreg(far_el1);
					item->insn = 0;
					rwpm_force_read_task(hwbp_handle_info->task, regs->pc, &item->insn, sizeof(item->insn));
				}
				hwbp_handle_info->trace_head = (idx + 1) % hwbp_handle_info->trace_capacity;
				if (hwbp_handle_info->trace_count < hwbp_handle_info->trace_capacity) {
					hwbp_handle_info->trace_count++;
				}
			}
			if (hwbp_handle_info->step_remaining > 0) {
				hwbp_handle_info->step_remaining--;
			}
			if (hwbp_handle_info->step_remaining > 0) {
				// some kernels clear single-step on exception, re-enable for next step
				x_user_enable_single_step(task);
				handled = DBG_HOOK_HANDLED;
				mutex_unlock(&hwbp_handle_info->hit_lock);
				break;
			}
			hwbp_handle_info->step_pending = false;
			x_user_disable_single_step(task);
			if (hwbp_handle_info->sample_hbp) {
				if (x_modify_user_hw_breakpoint(hwbp_handle_info->sample_hbp, &hwbp_handle_info->original_attr)) {
					toggle_bp_registers_directly(&hwbp_handle_info->original_attr, hwbp_handle_info->is_32bit_task, 1);
				}
			}
			handled = DBG_HOOK_HANDLED;
		}
		mutex_unlock(&hwbp_handle_info->hit_lock);
		break;
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	return handled;
}
#endif

/*
 * Handle hitting a HW-breakpoint.
 */
static void hwbp_handler(struct perf_event *bp,
	struct perf_sample_data *data,
	struct pt_regs *regs) {
	citerator iter;
	uint64_t hook_pc;
	printk_debug(KERN_INFO "hw_breakpoint HIT!!!!! bp:%px, pc:%px, id:%d\n", bp, regs->pc, bp->id);

	hook_pc = atomic64_read(&g_hook_pc);
	if(hook_pc) {
		regs->pc = hook_pc;
		return;
	}

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if (hwbp_handle_info->sample_hbp != bp) {
			continue;
		}
		mutex_lock(&hwbp_handle_info->hit_lock);
#ifdef CONFIG_USE_SINGLE_STEP_MODE
		hwbp_hit_user_info_callback(bp, data, regs, hwbp_handle_info);
		if (g_simulate_step_enabled && hwbp_handle_info->task &&
		    hwbp_handle_info->original_attr.bp_type == HW_BREAKPOINT_X) {
			struct perf_event_attr new_attr;
			u32 insn = 0;
			u64 next_pc = regs->pc + 4;
			if (read_user_insn_task(hwbp_handle_info->task, regs->pc, &insn)) {
				next_pc = calc_next_pc(regs, insn);
			}
			printk(KERN_INFO "wuji_step pc=0x%llx insn=0x%08x next=0x%llx\n",
			       (unsigned long long)regs->pc, insn, (unsigned long long)next_pc);
			step_log_push(hwbp_handle_info->task_id, regs->pc, insn, next_pc);
			memcpy(&new_attr, &hwbp_handle_info->original_attr, sizeof(new_attr));
			new_attr.bp_addr = next_pc;
			new_attr.bp_len = HW_BREAKPOINT_LEN_4;
			new_attr.bp_type = HW_BREAKPOINT_X;
			new_attr.disabled = 0;
			if (x_modify_user_hw_breakpoint(bp, &new_attr)) {
				toggle_bp_registers_directly(&hwbp_handle_info->original_attr, hwbp_handle_info->is_32bit_task, 0);
			} else {
				hwbp_handle_info->sim_next_attr = new_attr;
				hwbp_handle_info->sim_next_active = true;
			}
		} else if (hwbp_handle_info->task) {
			struct perf_event_attr new_attr;
			bool disabled_ok = true;
			hwbp_handle_info->step_pending = true;
			hwbp_handle_info->step_remaining = g_trace_enabled ? (g_trace_step_count ? g_trace_step_count : 1) : 1;
			memcpy(&new_attr, &hwbp_handle_info->original_attr, sizeof(new_attr));
			new_attr.disabled = 1;
			if (x_modify_user_hw_breakpoint(bp, &new_attr)) {
				disabled_ok = toggle_bp_registers_directly(&hwbp_handle_info->original_attr, hwbp_handle_info->is_32bit_task, 0);
			}
			if (!disabled_ok || x_user_enable_single_step(hwbp_handle_info->task) != 0) {
				hwbp_handle_info->step_pending = false;
				if (x_modify_user_hw_breakpoint(bp, &hwbp_handle_info->original_attr)) {
					toggle_bp_registers_directly(&hwbp_handle_info->original_attr, hwbp_handle_info->is_32bit_task, 1);
				}
			}
		}
#else
#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
		if(hwbp_handle_info->next_instruction_attr.bp_addr != regs->pc) {
			// first hit
			bool should_toggle = true;
			hwbp_hit_user_info_callback(bp, data, regs, hwbp_handle_info);
			if(!hwbp_handle_info->is_32bit_task) {
				if(arm64_move_bp_to_next_instruction(bp, regs->pc + 4, &hwbp_handle_info->original_attr, &hwbp_handle_info->next_instruction_attr)) {
					should_toggle = false;
				}
			}
			if(should_toggle) {
				toggle_bp_registers_directly(&hwbp_handle_info->original_attr, hwbp_handle_info->is_32bit_task, 0);
			}
		} else {
			// second hit
			if(!arm64_recovery_bp_to_original(bp, &hwbp_handle_info->original_attr, &hwbp_handle_info->next_instruction_attr)) {
				toggle_bp_registers_directly(&hwbp_handle_info->next_instruction_attr, hwbp_handle_info->is_32bit_task, 0);
			}
			/* record step log for trace mode */
			if (hwbp_handle_info->original_attr.bp_type == HW_BREAKPOINT_X && hwbp_handle_info->task) {
				u64 next_pc = regs->pc + 4;
				u32 insn = 0;
				if (read_user_insn_task(hwbp_handle_info->task, regs->pc, &insn)) {
					next_pc = calc_next_pc(regs, insn);
				}
				step_log_push(hwbp_handle_info->task_id, regs->pc, insn, next_pc);
				printk(KERN_INFO "wuji_step pc=0x%llx insn=0x%08x next=0x%llx\n",
				       (unsigned long long)regs->pc, insn, (unsigned long long)next_pc);
			}
		}
#else
		hwbp_hit_user_info_callback(bp, data, regs, hwbp_handle_info);
		toggle_bp_registers_directly(&hwbp_handle_info->original_attr, hwbp_handle_info->is_32bit_task, 0);
#endif
#endif
		mutex_unlock(&hwbp_handle_info->hit_lock);
	}
	
	mutex_unlock(&g_hwbp_handle_info_mutex);
}



static ssize_t OnCmdOpenProcess(struct ioctl_request *hdr, char __user* buf) {
	uint64_t pid = hdr->param1, handle = 0;
	struct pid * proc_pid_struct = NULL;
	printk_debug(KERN_INFO "CMD_OPEN_PROCESS\n");

	printk_debug(KERN_INFO "pid:%llu,size:%ld\n", pid, sizeof(pid));

	proc_pid_struct = get_proc_pid_struct(pid);
	printk_debug(KERN_INFO "proc_pid_struct *:0x%p\n", (void*)proc_pid_struct);
	if (!proc_pid_struct) {
		return -EINVAL;
	}
	handle = (uint64_t)proc_pid_struct;

	printk_debug(KERN_INFO "handle:%llu,size:%ld\n", handle, sizeof(handle));
	if (!!x_copy_to_user((void*)buf, (void*)&handle, sizeof(handle))) {
		return -EINVAL;
	}
	return 0;
}

static ssize_t OnCmdCloseProcess(struct ioctl_request *hdr, char __user* buf) {
	struct pid * proc_pid_struct = (struct pid *)hdr->param1;
	printk_debug(KERN_INFO "CMD_CLOSE_PROCESS\n");
	printk_debug(KERN_INFO "proc_pid_struct*:0x%p,size:%ld\n", (void*)proc_pid_struct, sizeof(proc_pid_struct));
	release_proc_pid_struct(proc_pid_struct);
	return 0;
}

static ssize_t OnCmdReadProcessMem(struct ioctl_request *hdr, char __user* buf) {
	struct pid * proc_pid_struct = (struct pid *)hdr->param1;
	uint64_t addr = hdr->param2;
	size_t size = hdr->buf_size;
	struct task_struct *task;
	void *kbuf;
	ssize_t read_bytes;
	if (!proc_pid_struct || !addr || size == 0) {
		return -EINVAL;
	}
	if (size > g_read_mem_max) {
		return -EINVAL;
	}
	task = pid_task(proc_pid_struct, PIDTYPE_PID);
	if (!task) {
		return -ESRCH;
	}
	kbuf = kmalloc(size, GFP_KERNEL);
	if (!kbuf) {
		return -ENOMEM;
	}
	read_bytes = rwpm_force_read_task(task, addr, kbuf, size);
	if (read_bytes <= 0) {
		kfree(kbuf);
		return -EFAULT;
	}
	if (x_copy_to_user((void*)buf, kbuf, read_bytes)) {
		kfree(kbuf);
		return -EFAULT;
	}
	kfree(kbuf);
	return read_bytes;
}

static ssize_t OnCmdReadUserInsn(struct ioctl_request *hdr, char __user* buf) {
	struct pid *proc_pid_struct = (struct pid *)hdr->param1;
	uint64_t pc = hdr->param2;
	struct task_struct *task;
	u32 insn = 0;

	if (!proc_pid_struct || !pc) {
		return -EINVAL;
	}
	task = pid_task(proc_pid_struct, PIDTYPE_PID);
	if (!task) {
		return -ESRCH;
	}
	if (!read_user_insn_task(task, pc, &insn)) {
		return -EFAULT;
	}
	if (x_copy_to_user((void*)buf, &insn, sizeof(insn))) {
		return -EFAULT;
	}
	return sizeof(insn);
}

static ssize_t OnCmdGetCpuNumBrps(struct ioctl_request *hdr, char __user* buf) {
	printk_debug(KERN_INFO "CMD_GET_NUM_BRPS\n");
	return getCpuNumBrps();
}

static ssize_t OnCmdGetCpuNumWrps(struct ioctl_request *hdr, char __user* buf) {
	printk_debug(KERN_INFO "CMD_GET_NUM_WRPS\n");
	return getCpuNumWrps();
}

static ssize_t OnCmdInstProcessHwbp(struct ioctl_request *hdr, char __user* buf) {
	struct pid * proc_pid_struct = (struct pid *)hdr->param1;
	citerator iter;
	uint64_t proc_virt_addr = hdr->param2;
	char hwbp_len  =  hdr->param3 & 0xFF;
	char hwbp_type = (hdr->param3 >> 8) & 0xFF;

	pid_t pid_val;
	struct task_struct *task;
	struct HWBP_HANDLE_INFO hwbp_handle_info = { 0 };
	printk_debug(KERN_INFO "CMD_INST_PROCESS_HWBP\n");
	printk_debug(KERN_INFO "proc_pid_struct *:%px\n", proc_pid_struct);
	printk_debug(KERN_INFO "proc_virt_addr :%px\n", proc_virt_addr);
	printk_debug(KERN_INFO "hwbp_len:%zu\n", hwbp_len);
	printk_debug(KERN_INFO "hwbp_type:%d\n", hwbp_type);

	pid_val = pid_nr(proc_pid_struct);
	printk_debug(KERN_INFO "pid_val:%d\n", pid_val);

	if (!pid_val) {
		printk_debug(KERN_INFO "pid_nr failed.\n");
		return -EINVAL;
	}

	task = pid_task(proc_pid_struct, PIDTYPE_PID);
	if (!task) {
		printk_debug(KERN_INFO "get_pid_task failed.\n");
		return -EINVAL;
	}
	
	hwbp_handle_info.task_id = pid_val;
	hwbp_handle_info.task = task;
	get_task_struct(task);
	hwbp_handle_info.is_32bit_task = is_compat_thread(task_thread_info(task));
	ptrace_breakpoint_init(&hwbp_handle_info.original_attr);
	hwbp_handle_info.original_attr.bp_addr = proc_virt_addr;
	hwbp_handle_info.original_attr.bp_len = hwbp_len;
	hwbp_handle_info.original_attr.bp_type = hwbp_type;
	hwbp_handle_info.original_attr.disabled = 0;
	hwbp_handle_info.sim_next_active = false;
	hwbp_handle_info.step_pending = false;
	hwbp_handle_info.step_remaining = 0;
	hwbp_handle_info.trace_buf = NULL;
	hwbp_handle_info.trace_capacity = 0;
	hwbp_handle_info.trace_item_size = 0;
	hwbp_handle_info.trace_head = 0;
	hwbp_handle_info.trace_count = 0;

	mutex_init(&hwbp_handle_info.hit_lock);

	hwbp_handle_info.sample_hbp = x_register_user_hw_breakpoint(&hwbp_handle_info.original_attr, hwbp_handler, NULL, task);
	printk_debug(KERN_INFO "register_user_hw_breakpoint return: %px\n", hwbp_handle_info.sample_hbp);
	if (IS_ERR((void __force *)hwbp_handle_info.sample_hbp)) {
		int ret = PTR_ERR((void __force *)hwbp_handle_info.sample_hbp);
		printk_debug(KERN_INFO "register_user_hw_breakpoint failed: %d\n", ret);
		return ret;
	}
	hwbp_handle_info.hit_item_arr = cvector_create(sizeof(struct HWBP_HIT_ITEM));
	mutex_lock(&g_hwbp_handle_info_mutex);
	cvector_pushback(g_hwbp_handle_info_arr, &hwbp_handle_info);
	mutex_unlock(&g_hwbp_handle_info_mutex);

	if (g_trace_enabled) {
		mutex_lock(&g_hwbp_handle_info_mutex);
		for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
			struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
			if (info->sample_hbp == hwbp_handle_info.sample_hbp) {
				mutex_lock(&info->hit_lock);
				trace_buffer_reset(info);
				mutex_unlock(&info->hit_lock);
				break;
			}
		}
		mutex_unlock(&g_hwbp_handle_info_mutex);
	}

	if (x_copy_to_user((void*)buf, &hwbp_handle_info.sample_hbp, sizeof(uint64_t))) {
		return -EINVAL;
	}
	return 0;
}

static ssize_t OnCmdUninstProcessHwbp(struct ioctl_request *hdr, char __user* buf) {
	struct perf_event * sample_hbp = (struct perf_event *)hdr->param1;
	citerator iter;
	bool found = false;
	struct task_struct *unreg_task = NULL;
	printk_debug(KERN_INFO "CMD_UNINST_PROCESS_HWBP\n");
	printk_debug(KERN_INFO "sample_hbp *:%px\n", sample_hbp);
	if(!sample_hbp) {
		return -EFAULT;
	}

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if(hwbp_handle_info->sample_hbp == sample_hbp) {
			mutex_lock(&hwbp_handle_info->hit_lock);
			unreg_task = hwbp_handle_info->task;
			hwbp_handle_info->task = NULL;
			if(hwbp_handle_info->hit_item_arr) {
				cvector_destroy(hwbp_handle_info->hit_item_arr);
				hwbp_handle_info->hit_item_arr = NULL;
			}
			trace_buffer_free(hwbp_handle_info);
			mutex_unlock(&hwbp_handle_info->hit_lock);
			mutex_destroy(&hwbp_handle_info->hit_lock);
			cvector_rm(g_hwbp_handle_info_arr, iter);
			found = true;
			break;
		}
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	if(found) {
		if (unreg_task) {
			put_task_struct(unreg_task);
		}
		x_unregister_hw_breakpoint(sample_hbp);
	}
	
	return 0;
}

static ssize_t OnCmdSuspendProcessHwbp(struct ioctl_request *hdr, char __user* buf) {
	struct perf_event * sample_hbp = (struct perf_event *)hdr->param1;
	struct perf_event_attr new_instruction_attr;
	citerator iter;
	bool found = false;
	printk_debug(KERN_INFO "CMD_SUSPEND_PROCESS_HWBP\n");
	printk_debug(KERN_INFO "sample_hbp *:%px\n", sample_hbp);
	if(!sample_hbp) {
		return -EFAULT;
	}

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if(hwbp_handle_info->sample_hbp == sample_hbp) {
			mutex_lock(&hwbp_handle_info->hit_lock);
			hwbp_handle_info->original_attr.disabled = 1;
			memcpy(&new_instruction_attr, &hwbp_handle_info->original_attr, sizeof(struct perf_event_attr));
			mutex_unlock(&hwbp_handle_info->hit_lock);
			found = true;
			break;
		}
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	if(found) {
		if(!x_modify_user_hw_breakpoint(sample_hbp, &new_instruction_attr)) {
			return 0;
		}
	}
	return -EFAULT;
}

static ssize_t OnCmdResumeProcessHwbp(struct ioctl_request *hdr, char __user* buf) {
	struct perf_event * sample_hbp = (struct perf_event *)hdr->param1;
	struct perf_event_attr new_instruction_attr;
	citerator iter;
	bool found = false;
	printk_debug(KERN_INFO "CMD_RESUME_PROCESS_HWBP\n");
	printk_debug(KERN_INFO "sample_hbp *:%px\n", sample_hbp);
	if(!sample_hbp) {
		return -EFAULT;
	}

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if(hwbp_handle_info->sample_hbp == sample_hbp) {
			mutex_lock(&hwbp_handle_info->hit_lock);
			hwbp_handle_info->original_attr.disabled = 0;
			memcpy(&new_instruction_attr, &hwbp_handle_info->original_attr, sizeof(struct perf_event_attr));
			mutex_unlock(&hwbp_handle_info->hit_lock);
			found = true;
			break;
		}
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	if(found) {
		if(!x_modify_user_hw_breakpoint(sample_hbp, &new_instruction_attr)) {
			return 0;
		}
	}
	return -EFAULT;
}

static ssize_t OnCmdGetHwbpHitCount(struct ioctl_request *hdr, char __user* buf) {
	#pragma pack(1)
	struct buf_layout {
		uint64_t hit_total_count;
		uint64_t hit_item_arr_count;
	};
	#pragma pack()
	struct perf_event *sample_hbp = (struct perf_event *)hdr->param1;
	struct buf_layout user_data = {0};
	citerator iter;
	printk_debug(KERN_INFO "CMD_GET_HWBP_HIT_COUNT\n");
	printk_debug(KERN_INFO "sample_hbp *:%px\n", sample_hbp);

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if (hwbp_handle_info->sample_hbp == sample_hbp && hwbp_handle_info->hit_item_arr) {
			mutex_lock(&hwbp_handle_info->hit_lock);
			user_data.hit_total_count = hwbp_handle_info->hit_total_count;
			user_data.hit_item_arr_count = cvector_length(hwbp_handle_info->hit_item_arr);
			mutex_unlock(&hwbp_handle_info->hit_lock);
			break;
		}
	}

	mutex_unlock(&g_hwbp_handle_info_mutex);
	
	printk_debug(KERN_INFO "user_data.hit_total_count:%zu\n", user_data.hit_total_count);
	if (x_copy_to_user((void*)buf, &user_data, sizeof(user_data))) {
		return -EINVAL;
	}
	return 0;
}

static ssize_t OnCmdGetHwbpHitDetail(struct ioctl_request *hdr, char __user* buf) {
	struct perf_event *sample_hbp = (struct perf_event *)hdr->param1;
	size_t size = hdr->buf_size;
	ssize_t count = 0;
	size_t copy_pos;
	size_t end_pos;

	citerator iter;
	printk_debug(KERN_INFO "sample_hbp *:%ld\n", sample_hbp);

	copy_pos = (size_t)buf;
	end_pos = (size_t)((size_t)buf + size);

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if (hwbp_handle_info->sample_hbp == sample_hbp && hwbp_handle_info->hit_item_arr) {
			citerator child;
			mutex_lock(&hwbp_handle_info->hit_lock);
			for (child = cvector_begin(hwbp_handle_info->hit_item_arr); child != cvector_end(hwbp_handle_info->hit_item_arr); child = cvector_next(hwbp_handle_info->hit_item_arr, child)) {
				struct HWBP_HIT_ITEM * hit_item = (struct HWBP_HIT_ITEM *)child;
				if (copy_pos >= end_pos) {
					break;
				}
				if (x_copy_to_user((void*)copy_pos, hit_item, sizeof(struct HWBP_HIT_ITEM))) {
					break;
				}
				copy_pos += sizeof(struct HWBP_HIT_ITEM);
				count++;
			}
			mutex_unlock(&hwbp_handle_info->hit_lock);
			break;
		}
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	return count;
}

static ssize_t OnCmdClearHwbpHit(struct ioctl_request *hdr, char __user* buf) {
	struct perf_event *sample_hbp = (struct perf_event *)hdr->param1;
	citerator iter;
	printk_debug(KERN_INFO "CMD_CLEAR_HWBP_HIT\n");
	printk_debug(KERN_INFO "sample_hbp *:%px\n", sample_hbp);
	if(!sample_hbp) {
		return -EFAULT;
	}

	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if (hwbp_handle_info->sample_hbp == sample_hbp) {
			mutex_lock(&hwbp_handle_info->hit_lock);
			hwbp_handle_info->hit_total_count = 0;
			if (hwbp_handle_info->hit_item_arr) {
				cvector_destroy(hwbp_handle_info->hit_item_arr);
			}
			hwbp_handle_info->hit_item_arr = cvector_create(sizeof(struct HWBP_HIT_ITEM));
			mutex_unlock(&hwbp_handle_info->hit_lock);
			mutex_unlock(&g_hwbp_handle_info_mutex);
			return 0;
		}
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	return -EINVAL;
}

static ssize_t OnCmdSetHookPc(struct ioctl_request *hdr, char __user* buf) {
	uint64_t pc = hdr->param1;
	printk_debug(KERN_INFO "CMD_SET_HOOK_PC\n");
	printk_debug(KERN_INFO "pc:%px\n", pc);
	if (!pc || pc >= TASK_SIZE) {
		return -EINVAL;
	}
	atomic64_set(&g_hook_pc, pc);
	return 0;
}

static ssize_t OnCmdHideKernelModule(struct ioctl_request *hdr, char __user* buf) {
	return -EOPNOTSUPP;
}



static ssize_t OnCmdSetTraceEnable(struct ioctl_request *hdr, char __user* buf) {
	bool enable = hdr->param1 ? true : false;
	citerator iter;
	g_trace_enabled = enable;
	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
		mutex_lock(&info->hit_lock);
		if (enable) {
			trace_buffer_reset(info);
		} else {
			trace_buffer_free(info);
		}
		mutex_unlock(&info->hit_lock);
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	return 0;
}

static ssize_t OnCmdSetTraceMode(struct ioctl_request *hdr, char __user* buf) {
	int mode = (int)hdr->param1;
	citerator iter;
	if (mode != TRACE_MODE_PC && mode != TRACE_MODE_FULL) {
		return -EINVAL;
	}
	g_trace_mode = mode;
	if (!g_trace_enabled) {
		return 0;
	}
	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
		mutex_lock(&info->hit_lock);
		trace_buffer_reset(info);
		mutex_unlock(&info->hit_lock);
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	return 0;
}

static ssize_t OnCmdSetTraceBufferSize(struct ioctl_request *hdr, char __user* buf) {
	size_t size = (size_t)hdr->param1;
	citerator iter;
	if (size == 0 || size > CONFIG_TRACE_MAX_SIZE) {
		return -EINVAL;
	}
	g_trace_capacity = size;
	if (!g_trace_enabled) {
		return 0;
	}
	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
		mutex_lock(&info->hit_lock);
		trace_buffer_reset(info);
		mutex_unlock(&info->hit_lock);
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	return 0;
}

static ssize_t OnCmdSetTraceStepCount(struct ioctl_request *hdr, char __user* buf) {
	size_t count = (size_t)hdr->param1;
	if (count == 0 || count > CONFIG_TRACE_MAX_STEP) {
		return -EINVAL;
	}
	g_trace_step_count = count;
	return 0;
}

static ssize_t OnCmdSetStepSimulate(struct ioctl_request *hdr, char __user* buf) {
	bool enable = hdr->param1 ? true : false;
	citerator iter;
	g_simulate_step_enabled = enable;
	if (enable) {
		return 0;
	}
	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
		mutex_lock(&info->hit_lock);
		if (info->sim_next_active && info->sample_hbp) {
			if (x_modify_user_hw_breakpoint(info->sample_hbp, &info->original_attr)) {
				toggle_bp_registers_directly(&info->original_attr, info->is_32bit_task, 1);
			}
			info->sim_next_active = false;
		}
		mutex_unlock(&info->hit_lock);
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	return 0;
}

static ssize_t OnCmdGetTraceCount(struct ioctl_request *hdr, char __user* buf) {
	#pragma pack(1)
	struct trace_count_data {
		uint64_t count;
		uint64_t capacity;
		uint64_t item_size;
		uint64_t mode;
	};
	#pragma pack()
	struct perf_event * sample_hbp = (struct perf_event *)hdr->param1;
	struct trace_count_data out = {0};	
	citerator iter;
	if (!sample_hbp) return -EINVAL;
	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
		if (info->sample_hbp == sample_hbp) {
			mutex_lock(&info->hit_lock);
			out.count = info->trace_count;
			out.capacity = info->trace_capacity;
			out.item_size = info->trace_item_size;
			out.mode = g_trace_mode;
			mutex_unlock(&info->hit_lock);
			break;
		}
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	if (x_copy_to_user((void*)buf, &out, sizeof(out))) {
		return -EFAULT;
	}
	return 0;
}

static ssize_t OnCmdGetTraceData(struct ioctl_request *hdr, char __user* buf) {
	struct perf_event *sample_hbp = (struct perf_event *)hdr->param1;
	size_t size = hdr->buf_size;
	citerator iter;
	ssize_t copied = 0;
	if (!sample_hbp || size == 0) return -EINVAL;
	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
		if (info->sample_hbp == sample_hbp) {
			mutex_lock(&info->hit_lock);
			if (!info->trace_buf || info->trace_item_size == 0) {
				mutex_unlock(&info->hit_lock);
				mutex_unlock(&g_hwbp_handle_info_mutex);
				return -EINVAL;
			}
			{
				size_t count = info->trace_count;
				size_t item_size = info->trace_item_size;
				size_t max_items = size / item_size;
				size_t to_copy = (count < max_items) ? count : max_items;
				size_t start = (info->trace_head + info->trace_capacity - info->trace_count) % info->trace_capacity;
				char *dst = (char *)buf;
				char *src = (char *)info->trace_buf;
				size_t i;
				for (i = 0; i < to_copy; ++i) {
					size_t idx = (start + i) % info->trace_capacity;
					if (x_copy_to_user(dst + i * item_size, src + idx * item_size, item_size)) {
						break;
					}
				}
				copied = (ssize_t)i;
				if (i == to_copy) {
					info->trace_count = 0;
				}
			}
			mutex_unlock(&info->hit_lock);
			break;
		}
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	return copied;
}

static ssize_t OnCmdGetStepLog(struct ioctl_request *hdr, char __user* buf) {
	unsigned long flags;
	size_t max_items;
	size_t to_copy;
	size_t start;
	size_t i;
	struct STEP_LOG_ITEM *tmp;
	size_t size = hdr->buf_size;
	if (!buf || size < sizeof(struct STEP_LOG_ITEM))
		return -EINVAL;
	max_items = size / sizeof(struct STEP_LOG_ITEM);
	spin_lock_irqsave(&g_step_log_lock, flags);
	to_copy = g_step_log_count;
	if (to_copy > max_items)
		to_copy = max_items;
	start = (g_step_log_head + STEP_LOG_CAPACITY - g_step_log_count) % STEP_LOG_CAPACITY;
	spin_unlock_irqrestore(&g_step_log_lock, flags);

	if (to_copy == 0)
		return 0;

	tmp = kmalloc(sizeof(struct STEP_LOG_ITEM) * to_copy, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	spin_lock_irqsave(&g_step_log_lock, flags);
	for (i = 0; i < to_copy; ++i) {
		size_t idx = (start + i) % STEP_LOG_CAPACITY;
		memcpy(&tmp[i], &g_step_log[idx], sizeof(struct STEP_LOG_ITEM));
	}
	g_step_log_count = 0;
	g_step_log_head = 0;
	spin_unlock_irqrestore(&g_step_log_lock, flags);

	if (x_copy_to_user((void*)buf, tmp, sizeof(struct STEP_LOG_ITEM) * to_copy)) {
		kfree(tmp);
		return -EFAULT;
	}
	kfree(tmp);
	return (ssize_t)(to_copy * sizeof(struct STEP_LOG_ITEM));
}
ssize_t hwbp_dispatch(struct ioctl_request *hdr, char __user* buf) {
	switch (hdr->cmd) {
	case CMD_HWBP_OPEN_PROCESS:
		return OnCmdOpenProcess(hdr, buf);
	case CMD_HWBP_CLOSE_PROCESS:
		return OnCmdCloseProcess(hdr, buf);
	case CMD_HWBP_READ_PROCESS_MEM:
		return OnCmdReadProcessMem(hdr, buf);
	case CMD_HWBP_READ_USER_INSN:
		return OnCmdReadUserInsn(hdr, buf);
	case CMD_HWBP_GET_NUM_BRPS:
		return OnCmdGetCpuNumBrps(hdr, buf);
	case CMD_HWBP_GET_NUM_WRPS:
		return OnCmdGetCpuNumWrps(hdr, buf);
	case CMD_HWBP_INST_PROCESS_HWBP:
		return OnCmdInstProcessHwbp(hdr, buf);
	case CMD_HWBP_UNINST_PROCESS_HWBP:
		return OnCmdUninstProcessHwbp(hdr, buf);
	case CMD_HWBP_SUSPEND_PROCESS_HWBP:
		return OnCmdSuspendProcessHwbp(hdr, buf);
	case CMD_HWBP_RESUME_PROCESS_HWBP:
		return OnCmdResumeProcessHwbp(hdr, buf);
	case CMD_HWBP_GET_HWBP_HIT_COUNT:
		return OnCmdGetHwbpHitCount(hdr, buf);
	case CMD_HWBP_GET_HWBP_HIT_DETAIL:
		return OnCmdGetHwbpHitDetail(hdr, buf);
	case CMD_HWBP_CLEAR_HWBP_HIT:
		return OnCmdClearHwbpHit(hdr, buf);
	case CMD_HWBP_SET_HOOK_PC:
		return OnCmdSetHookPc(hdr, buf);
	case CMD_HWBP_SET_TRACE_ENABLE:
		return OnCmdSetTraceEnable(hdr, buf);
	case CMD_HWBP_SET_TRACE_MODE:
		return OnCmdSetTraceMode(hdr, buf);
	case CMD_HWBP_SET_TRACE_BUFFER_SIZE:
		return OnCmdSetTraceBufferSize(hdr, buf);
	case CMD_HWBP_SET_TRACE_STEP_COUNT:
		return OnCmdSetTraceStepCount(hdr, buf);
	case CMD_HWBP_SET_STEP_SIMULATE:
		return OnCmdSetStepSimulate(hdr, buf);
	case CMD_HWBP_GET_TRACE_COUNT:
		return OnCmdGetTraceCount(hdr, buf);
	case CMD_HWBP_GET_TRACE_DATA:
		return OnCmdGetTraceData(hdr, buf);
	case CMD_HWBP_GET_STEP_LOG:
		return OnCmdGetStepLog(hdr, buf);
	case CMD_HWBP_HIDE_KERNEL_MODULE:
		return OnCmdHideKernelModule(hdr, buf);
	default:
		return -EINVAL;
	}
	return -EINVAL;
}

static void clean_hwbp(void) {
	citerator iter;
	cvector wait_unregister_bp_arr = cvector_create(sizeof(struct perf_event *));
	if(!wait_unregister_bp_arr || !g_hwbp_handle_info_arr) {
		return;
	}
	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO * hwbp_handle_info = (struct HWBP_HANDLE_INFO *)iter;
		if(hwbp_handle_info->sample_hbp) {
			cvector_pushback(wait_unregister_bp_arr, &hwbp_handle_info->sample_hbp);
			hwbp_handle_info->sample_hbp = NULL;
		}
		mutex_lock(&hwbp_handle_info->hit_lock);
		if (hwbp_handle_info->task) {
			put_task_struct(hwbp_handle_info->task);
			hwbp_handle_info->task = NULL;
		}
		if(hwbp_handle_info->hit_item_arr) {
			cvector_destroy(hwbp_handle_info->hit_item_arr);
			hwbp_handle_info->hit_item_arr = NULL;
		}
		trace_buffer_free(hwbp_handle_info);
		mutex_unlock(&hwbp_handle_info->hit_lock);
		mutex_destroy(&hwbp_handle_info->hit_lock);
	}
	cvector_destroy(g_hwbp_handle_info_arr);
	g_hwbp_handle_info_arr = NULL;
	mutex_unlock(&g_hwbp_handle_info_mutex);
	
	for (iter = cvector_begin(wait_unregister_bp_arr); iter != cvector_end(wait_unregister_bp_arr); iter = cvector_next(wait_unregister_bp_arr, iter)) {
	  struct perf_event * bp = *(struct perf_event **)iter;
	  x_unregister_hw_breakpoint(bp);
	}
	cvector_destroy(wait_unregister_bp_arr);
}

int hwbp_release(struct inode *inode, struct file *filp) {
	clean_hwbp();
	mutex_lock(&g_hwbp_handle_info_mutex);
	g_hwbp_handle_info_arr = cvector_create(sizeof(struct HWBP_HANDLE_INFO));
	mutex_unlock(&g_hwbp_handle_info_mutex);
	return 0;
}

int hwbp_init(void) {
#ifdef CONFIG_KALLSYMS_LOOKUP_NAME
	if(!init_kallsyms_lookup()) {
		printk(KERN_EMERG "init_kallsyms_lookup failed\n");
		return -EBADF;
	}
#endif
	g_hwbp_handle_info_arr = cvector_create(sizeof(struct HWBP_HANDLE_INFO));
	mutex_init(&g_hwbp_handle_info_mutex);

#ifdef CONFIG_ANTI_PTRACE_DETECTION_MODE
	start_anti_ptrace_detection(&g_hwbp_handle_info_mutex, &g_hwbp_handle_info_arr);
#endif

#ifdef CONFIG_USE_SINGLE_STEP_MODE
	g_step_hook.fn = hwbp_step_hook;
	if (x_register_step_hook(&g_step_hook) == 0) {
		g_step_hook_installed = true;
	} else {
		printk_debug(KERN_EMERG "register_step_hook failed, single-step disabled\n");
	}
#endif
	return 0;
}

void hwbp_exit(void) {
#ifdef CONFIG_ANTI_PTRACE_DETECTION_MODE
	stop_anti_ptrace_detection();
#endif

#ifdef CONFIG_USE_SINGLE_STEP_MODE
	if (g_step_hook_installed) {
		x_unregister_step_hook(&g_step_hook);
		g_step_hook_installed = false;
	}
#endif

	clean_hwbp();
	
	mutex_destroy(&g_hwbp_handle_info_mutex);
}
