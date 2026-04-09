#include "hwbp_module.h"
#include "phy_mem.h"
#include "proc_pid.h"
#include "api_proxy.h"
#include "anti_ptrace_detection.h"
#include "anti_status_tracerpid.h"
#include "rwpm_ioctl.h"
#include <asm/debug-monitors.h>
#include <asm/sysreg.h>
#include <linux/ptrace.h>
#include <linux/list.h>
#include <linux/spinlock.h>

extern ssize_t rwpm_force_read_task(struct task_struct *task, size_t addr, void *dst, size_t size);
//////////////////////////////////////////////////////////////////

static atomic64_t g_hook_pc;

// Driver log ring buffer
#define DRIVER_LOG_CAP 65536
static char g_driver_log_buf[DRIVER_LOG_CAP];
static size_t g_driver_log_head;
static size_t g_driver_log_len;
static DEFINE_SPINLOCK(g_driver_log_lock);

static void driver_log_write(const char *s, size_t len)
{
	unsigned long flags;
	size_t cap = DRIVER_LOG_CAP;
	size_t first;
	if (!s || len == 0)
		return;
	if (len > cap) {
		s += (len - cap);
		len = cap;
	}
	spin_lock_irqsave(&g_driver_log_lock, flags);
	first = cap - g_driver_log_head;
	if (first > len)
		first = len;
	memcpy(g_driver_log_buf + g_driver_log_head, s, first);
	if (len > first) {
		memcpy(g_driver_log_buf, s + first, len - first);
	}
	g_driver_log_head = (g_driver_log_head + len) % cap;
	if (g_driver_log_len + len >= cap)
		g_driver_log_len = cap;
	else
		g_driver_log_len += len;
	spin_unlock_irqrestore(&g_driver_log_lock, flags);
}

void drv_logf(const char *fmt, ...)
{
	va_list args;
	char tmp[256];
	int n;
	if (!fmt) return;
	va_start(args, fmt);
	n = vsnprintf(tmp, sizeof(tmp), fmt, args);
	va_end(args);
	if (n <= 0) return;
	if (n >= (int)sizeof(tmp)) n = (int)sizeof(tmp) - 1;
	driver_log_write(tmp, (size_t)n);
	if (tmp[n - 1] != '\n')
		driver_log_write("\n", 1);
}

static struct mutex g_hwbp_handle_info_mutex;
static cvector g_hwbp_handle_info_arr = NULL;
static DEFINE_SPINLOCK(g_bp_restore_lock);

struct bp_step_restore_item {
	struct list_head node;
	struct HWBP_HANDLE_INFO *info;
	struct perf_event *bp;
	struct perf_event_attr original_attr;
	struct task_struct *task;
	bool is_32bit_task;
};

static LIST_HEAD(g_bp_restore_list);
static struct step_hook g_bp_step_hook;
static int hwbp_single_step_restore_hook(struct pt_regs *regs, unsigned int esr);

static size_t g_trace_step_count = CONFIG_TRACE_DEFAULT_STEP;
static int g_step_filter_mode = STEP_FILTER_ALL;
static atomic64_t g_step_budget_remaining = ATOMIC64_INIT(0);
static atomic64_t g_step_tracked_tid = ATOMIC64_INIT(-1);
static DEFINE_SPINLOCK(g_step_log_lock);
#define STEP_LOG_CAPACITY 8192
static struct STEP_LOG_ITEM g_step_log[STEP_LOG_CAPACITY];
static size_t g_step_log_head;
static size_t g_step_log_tail;
static size_t g_step_log_count;
static atomic64_t g_step_seq = ATOMIC_INIT(0);
static bool g_step_session_running;
static bool g_step_session_done;
static u32 g_step_stop_reason;
static size_t g_step_requested_count;

static void step_session_buffer_reset_locked(void)
{
	g_step_log_head = 0;
	g_step_log_tail = 0;
	g_step_log_count = 0;
}

static void step_session_mark_done(u32 reason)
{
	unsigned long flags;
	spin_lock_irqsave(&g_step_log_lock, flags);
	g_step_session_running = false;
	g_step_session_done = true;
	g_step_stop_reason = reason;
	spin_unlock_irqrestore(&g_step_log_lock, flags);
}

static void step_session_start(size_t requested_steps)
{
	unsigned long flags;
	spin_lock_irqsave(&g_step_log_lock, flags);
	step_session_buffer_reset_locked();
	g_step_session_running = true;
	g_step_session_done = false;
	g_step_stop_reason = STEP_STOP_NONE;
	g_step_requested_count = requested_steps;
	spin_unlock_irqrestore(&g_step_log_lock, flags);
	atomic64_set(&g_step_seq, 0);
	atomic64_set(&g_step_budget_remaining, (s64)requested_steps);
	atomic64_set(&g_step_tracked_tid, -1);
}

static bool step_session_is_running(void)
{
	unsigned long flags;
	bool running;
	spin_lock_irqsave(&g_step_log_lock, flags);
	running = g_step_session_running;
	spin_unlock_irqrestore(&g_step_log_lock, flags);
	return running;
}

static bool hwbp_queue_single_step_restore(struct HWBP_HANDLE_INFO *info)
{
	struct bp_step_restore_item *item;
	unsigned long flags;

	if (!info || info->bp_restore_pending) {
		return true;
	}

	item = kmalloc(sizeof(*item), GFP_ATOMIC);
	if (!item) {
		return false;
	}

	item->info = info;
	item->bp = info->sample_hbp;
	item->original_attr = info->original_attr;
	item->task = info->task;
	get_task_struct(item->task);
	item->is_32bit_task = info->is_32bit_task;
	spin_lock_irqsave(&g_bp_restore_lock, flags);
	if (info->bp_restore_pending) {
		spin_unlock_irqrestore(&g_bp_restore_lock, flags);
		put_task_struct(item->task);
		kfree(item);
		return true;
	}
	info->bp_restore_pending = true;
	list_add_tail(&item->node, &g_bp_restore_list);
	spin_unlock_irqrestore(&g_bp_restore_lock, flags);
	return true;
}

static void hwbp_clear_single_step_restore(struct HWBP_HANDLE_INFO *info)
{
	struct bp_step_restore_item *item, *tmp;
	unsigned long flags;

	if (!info) {
		return;
	}

	spin_lock_irqsave(&g_bp_restore_lock, flags);
	list_for_each_entry_safe(item, tmp, &g_bp_restore_list, node) {
		if (item->info != info) {
			continue;
		}
		list_del(&item->node);
		info->bp_restore_pending = false;
		spin_unlock_irqrestore(&g_bp_restore_lock, flags);
		put_task_struct(item->task);
		kfree(item);
		return;
	}
	info->bp_restore_pending = false;
	spin_unlock_irqrestore(&g_bp_restore_lock, flags);
}

static void hwbp_clear_all_single_step_restores(void)
{
	struct bp_step_restore_item *item, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&g_bp_restore_lock, flags);
	list_for_each_entry_safe(item, tmp, &g_bp_restore_list, node) {
		list_del(&item->node);
		if (item->info) {
			item->info->bp_restore_pending = false;
		}
		if (item->task) {
			put_task_struct(item->task);
		}
		kfree(item);
	}
	spin_unlock_irqrestore(&g_bp_restore_lock, flags);
}

static int hwbp_single_step_restore_hook(struct pt_regs *regs, unsigned int esr)
{
	struct bp_step_restore_item *item, *tmp;
	unsigned long flags;
	bool found = false;

	if (!user_mode(regs)) {
		return DBG_HOOK_ERROR;
	}

	spin_lock_irqsave(&g_bp_restore_lock, flags);
	list_for_each_entry_safe(item, tmp, &g_bp_restore_list, node) {
		if (!item->task || item->task != current) {
			continue;
		}
		list_del(&item->node);
		if (item->info) {
			item->info->bp_restore_pending = false;
		}
		if (item->bp) {
			struct perf_event_attr restore_attr = item->original_attr;
			restore_attr.disabled = 0;
			if (x_modify_user_hw_breakpoint(item->bp, &restore_attr)) {
				toggle_bp_registers_directly(&restore_attr, item->is_32bit_task, 1);
			}
		}
		put_task_struct(item->task);
		kfree(item);
		found = true;
	}
	spin_unlock_irqrestore(&g_bp_restore_lock, flags);

	if (!found) {
		return DBG_HOOK_ERROR;
	}

	user_disable_single_step(current);
	return DBG_HOOK_HANDLED;
}

static __maybe_unused bool step_log_push(uint64_t tid, uint64_t pc, uint32_t insn, uint64_t next_pc, bool is_branch)
{
	unsigned long flags;
	spin_lock_irqsave(&g_step_log_lock, flags);
	if (g_step_log_count >= STEP_LOG_CAPACITY) {
		spin_unlock_irqrestore(&g_step_log_lock, flags);
		return false;
	}
	g_step_log[g_step_log_head].task_id = tid;
	g_step_log[g_step_log_head].pc = pc;
	g_step_log[g_step_log_head].next_pc = next_pc;
	g_step_log[g_step_log_head].insn = insn;
	g_step_log[g_step_log_head].flags = is_branch ? 1 : 0;
	g_step_log[g_step_log_head].seq = atomic64_inc_return(&g_step_seq);
	g_step_log_head = (g_step_log_head + 1) % STEP_LOG_CAPACITY;
	g_step_log_count++;
	spin_unlock_irqrestore(&g_step_log_lock, flags);
	return true;
}
static bool g_simulate_step_enabled = false;
static const size_t g_read_mem_max = (size_t)-1;

static inline s64 sign_extend_64(u64 val, int bits) {
    u64 shift = 64 - (u64)bits;
    return (s64)((val << shift)) >> shift;
}

static inline bool is_branch_step(u64 pc, u64 next_pc) {
	return next_pc != pc + 4;
}

static __maybe_unused bool step_log_maybe_push(uint64_t tid, uint64_t pc, uint32_t insn, uint64_t next_pc)
{
	bool is_branch = is_branch_step(pc, next_pc);
	if (g_step_filter_mode == STEP_FILTER_BRANCH_ONLY && !is_branch) {
		return true;
	}
	return step_log_push(tid, pc, insn, next_pc, is_branch);
}

static void disable_step_simulation_for_all_handles_locked(struct HWBP_HANDLE_INFO *skip)
{
	citerator iter;
	struct perf_event_attr disabled_attr;
	g_simulate_step_enabled = false;
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
		if (info == skip) {
			continue;
		}
		mutex_lock(&info->hit_lock);
		info->step_pending = false;
		info->step_exhausted = true;
		if (info->sample_hbp) {
			disabled_attr = info->original_attr;
			disabled_attr.disabled = 1;
			if (info->sim_next_active) {
				if (x_modify_user_hw_breakpoint(info->sample_hbp, &disabled_attr)) {
#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
					toggle_bp_registers_directly(&disabled_attr, info->is_32bit_task, 1);
#endif
				}
				info->sim_next_active = false;
			} else {
				if (x_modify_user_hw_breakpoint(info->sample_hbp, &disabled_attr)) {
#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
					toggle_bp_registers_directly(&disabled_attr, info->is_32bit_task, 1);
#endif
				}
			}
		}
		mutex_unlock(&info->hit_lock);
	}
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
#ifdef CONFIG_MODIFY_HIT_NEXT_MODE
		if (g_simulate_step_enabled &&
		    step_session_is_running() &&
		    hwbp_handle_info->task &&
		    hwbp_handle_info->original_attr.bp_type == HW_BREAKPOINT_X) {
			s64 tracked_tid;
			long budget_left;
			u64 next_pc = regs->pc + 4;
			u32 insn = 0;
			bool have_insn = false;
			bool logged = false;
			tracked_tid = atomic64_read(&g_step_tracked_tid);
			if (tracked_tid < 0) {
				tracked_tid = atomic64_cmpxchg(&g_step_tracked_tid, -1, (s64)hwbp_handle_info->task_id);
				if (tracked_tid < 0) {
					tracked_tid = (s64)hwbp_handle_info->task_id;
				}
			}
			if ((u64)tracked_tid != hwbp_handle_info->task_id) {
				mutex_unlock(&hwbp_handle_info->hit_lock);
				continue;
			}
			budget_left = atomic64_dec_if_positive(&g_step_budget_remaining);
			if (budget_left < 0) {
				if (hwbp_handle_info->sample_hbp) {
					struct perf_event_attr disabled_attr = hwbp_handle_info->original_attr;
					disabled_attr.disabled = 1;
					hwbp_handle_info->step_pending = false;
					hwbp_handle_info->step_exhausted = true;
					if (x_modify_user_hw_breakpoint(hwbp_handle_info->sample_hbp, &disabled_attr)) {
						toggle_bp_registers_directly(&disabled_attr, hwbp_handle_info->is_32bit_task, 1);
					}
					hwbp_handle_info->sim_next_active = false;
				}
				disable_step_simulation_for_all_handles_locked(hwbp_handle_info);
				mutex_unlock(&hwbp_handle_info->hit_lock);
				continue;
			}
			if (!hwbp_handle_info->step_pending) {
				hwbp_hit_user_info_callback(bp, data, regs, hwbp_handle_info);
				hwbp_handle_info->step_pending = true;
				hwbp_handle_info->step_remaining = 0;
			}
			have_insn = read_user_insn_task(hwbp_handle_info->task, regs->pc, &insn);
			if (have_insn) {
				next_pc = calc_next_pc(regs, insn);
			}
			if (!have_insn) {
				step_session_mark_done(STEP_STOP_READ_INSN_FAILED);
				hwbp_handle_info->step_pending = false;
				hwbp_handle_info->step_exhausted = true;
				if (hwbp_handle_info->sim_next_active && hwbp_handle_info->sample_hbp) {
					if (x_modify_user_hw_breakpoint(hwbp_handle_info->sample_hbp, &hwbp_handle_info->original_attr)) {
						toggle_bp_registers_directly(&hwbp_handle_info->original_attr, hwbp_handle_info->is_32bit_task, 1);
					}
					hwbp_handle_info->sim_next_active = false;
				}
				disable_step_simulation_for_all_handles_locked(hwbp_handle_info);
				mutex_unlock(&hwbp_handle_info->hit_lock);
				continue;
			}
			if (!next_pc) {
				step_session_mark_done(STEP_STOP_NEXT_PC_INVALID);
				hwbp_handle_info->step_pending = false;
				hwbp_handle_info->step_exhausted = true;
				if (hwbp_handle_info->sim_next_active && hwbp_handle_info->sample_hbp) {
					if (x_modify_user_hw_breakpoint(hwbp_handle_info->sample_hbp, &hwbp_handle_info->original_attr)) {
						toggle_bp_registers_directly(&hwbp_handle_info->original_attr, hwbp_handle_info->is_32bit_task, 1);
					}
					hwbp_handle_info->sim_next_active = false;
				}
				disable_step_simulation_for_all_handles_locked(hwbp_handle_info);
				mutex_unlock(&hwbp_handle_info->hit_lock);
				continue;
			}
			logged = step_log_maybe_push(hwbp_handle_info->task_id, regs->pc, insn, next_pc);
			if (!logged) {
				step_session_mark_done(STEP_STOP_BUFFER_FULL);
				hwbp_handle_info->step_pending = false;
				hwbp_handle_info->step_exhausted = true;
				if (hwbp_handle_info->sim_next_active && hwbp_handle_info->sample_hbp) {
					if (x_modify_user_hw_breakpoint(hwbp_handle_info->sample_hbp, &hwbp_handle_info->original_attr)) {
						toggle_bp_registers_directly(&hwbp_handle_info->original_attr, hwbp_handle_info->is_32bit_task, 1);
					}
					hwbp_handle_info->sim_next_active = false;
				}
				disable_step_simulation_for_all_handles_locked(hwbp_handle_info);
				mutex_unlock(&hwbp_handle_info->hit_lock);
				continue;
			}
			if (budget_left == 0) {
				hwbp_handle_info->step_pending = false;
				if (hwbp_handle_info->sim_next_active && hwbp_handle_info->sample_hbp) {
					if (x_modify_user_hw_breakpoint(hwbp_handle_info->sample_hbp, &hwbp_handle_info->original_attr)) {
						toggle_bp_registers_directly(&hwbp_handle_info->original_attr, hwbp_handle_info->is_32bit_task, 1);
					}
					hwbp_handle_info->sim_next_active = false;
				}
				if (budget_left == 0 && hwbp_handle_info->sample_hbp) {
					struct perf_event_attr disabled_attr = hwbp_handle_info->original_attr;
					disabled_attr.disabled = 1;
					hwbp_handle_info->step_exhausted = true;
					step_session_mark_done(STEP_STOP_COUNT_REACHED);
					if (x_modify_user_hw_breakpoint(hwbp_handle_info->sample_hbp, &disabled_attr)) {
						toggle_bp_registers_directly(&disabled_attr, hwbp_handle_info->is_32bit_task, 1);
					}
					hwbp_handle_info->sim_next_active = false;
					disable_step_simulation_for_all_handles_locked(hwbp_handle_info);
				}
				mutex_unlock(&hwbp_handle_info->hit_lock);
				continue;
			}
			{
				struct perf_event_attr new_attr;
				memcpy(&new_attr, &hwbp_handle_info->original_attr, sizeof(new_attr));
				new_attr.bp_addr = next_pc;
				new_attr.bp_len = HW_BREAKPOINT_LEN_4;
				new_attr.bp_type = HW_BREAKPOINT_X;
				new_attr.disabled = 0;
				if (x_modify_user_hw_breakpoint(bp, &new_attr)) {
					step_session_mark_done(STEP_STOP_BP_RESTORE_FAILED);
					toggle_bp_registers_directly(&hwbp_handle_info->original_attr, hwbp_handle_info->is_32bit_task, 0);
					disable_step_simulation_for_all_handles_locked(hwbp_handle_info);
					hwbp_handle_info->sim_next_active = false;
				} else {
					hwbp_handle_info->sim_next_attr = new_attr;
					hwbp_handle_info->sim_next_active = true;
				}
			}
			mutex_unlock(&hwbp_handle_info->hit_lock);
			continue;
		}
		if (hwbp_handle_info->original_attr.bp_type == HW_BREAKPOINT_X) {
			bool disabled_ok = false;
			hwbp_hit_user_info_callback(bp, data, regs, hwbp_handle_info);
			if (hwbp_handle_info->sample_hbp) {
				struct perf_event_attr disabled_attr = hwbp_handle_info->original_attr;
				disabled_attr.disabled = 1;
				if (x_modify_user_hw_breakpoint(hwbp_handle_info->sample_hbp, &disabled_attr)) {
					disabled_ok = true;
				} else if (toggle_bp_registers_directly(&disabled_attr, hwbp_handle_info->is_32bit_task, 0)) {
					disabled_ok = true;
				}
			}
			if (disabled_ok) {
				if (!hwbp_queue_single_step_restore(hwbp_handle_info)) {
					struct perf_event_attr restore_attr = hwbp_handle_info->original_attr;
					restore_attr.disabled = 0;
					if (x_modify_user_hw_breakpoint(hwbp_handle_info->sample_hbp, &restore_attr)) {
						toggle_bp_registers_directly(&restore_attr, hwbp_handle_info->is_32bit_task, 1);
					}
				} else {
					user_enable_single_step(current);
				}
			}
			mutex_unlock(&hwbp_handle_info->hit_lock);
			continue;
		}
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
				step_log_maybe_push(hwbp_handle_info->task_id, regs->pc, insn, next_pc);
				printk(KERN_INFO "wuji_step pc=0x%llx insn=0x%08x next=0x%llx\n",
				       (unsigned long long)regs->pc, insn, (unsigned long long)next_pc);
			}
		}
#else
		hwbp_hit_user_info_callback(bp, data, regs, hwbp_handle_info);
		toggle_bp_registers_directly(&hwbp_handle_info->original_attr, hwbp_handle_info->is_32bit_task, 0);
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

static ssize_t OnCmdWriteProcessMem(struct ioctl_request *hdr, char __user* buf) {
	struct pid * proc_pid_struct = (struct pid *)hdr->param1;
	uint64_t addr = hdr->param2;
	size_t size = hdr->buf_size;
	size_t write_size = 0;

	if (!proc_pid_struct || !addr || size == 0) {
		return -EINVAL;
	}

	while (write_size < size) {
		size_t phy_addr = 0;
		size_t pfn_sz = 0;
		pte_t *pte;
		bool old_pte_can_write;
		char *input_buf;

		phy_addr = get_proc_phy_addr(proc_pid_struct, addr + write_size, &pte);
		if (phy_addr == 0) {
			break;
		}

		old_pte_can_write = is_pte_can_write(pte);
		if (!old_pte_can_write) {
			if (!change_pte_write_status(pte, true)) {
				break;
			}
		}

		pfn_sz = size_inside_page(phy_addr, ((size - write_size) > PAGE_SIZE) ? PAGE_SIZE : (size - write_size));
		input_buf = (char *)((size_t)buf + write_size);
		if (write_ram_physical_addr(phy_addr, input_buf, false, pfn_sz) == 0) {
			if (!old_pte_can_write) {
				change_pte_write_status(pte, false);
			}
			break;
		}
		if (!old_pte_can_write) {
			change_pte_write_status(pte, false);
		}
		write_size += pfn_sz;
	}
	return write_size;
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

static ssize_t OnCmdSetTracerPidHide(struct ioctl_request *hdr, char __user* buf) {
	pid_t tgid = (pid_t)hdr->param1;
	(void)buf;
	if (tgid == 0) {
		printk_debug(KERN_INFO "TracerPid hide: clear\n");
		tracerpid_clear_all();
		return 0;
	}
	printk_debug(KERN_INFO "TracerPid hide: tgid=%d\n", tgid);
	if (!install_status_probe()) {
		return -EFAULT;
	}
	tracerpid_clear_all();
	tracerpid_add_tid(tgid);
	return 0;
}

static ssize_t OnCmdTracerPidAddTid(struct ioctl_request *hdr, char __user* buf) {
	pid_t tid = (pid_t)hdr->param1;
	(void)buf;
	if (tid <= 0)
		return -EINVAL;
	printk_debug(KERN_INFO "TracerPid add tid=%d\n", tid);
	if (!install_status_probe()) {
		return -EFAULT;
	}
	return tracerpid_add_tid(tid);
}

static ssize_t OnCmdTracerPidDelTid(struct ioctl_request *hdr, char __user* buf) {
	pid_t tid = (pid_t)hdr->param1;
	(void)buf;
	if (tid <= 0)
		return -EINVAL;
	printk_debug(KERN_INFO "TracerPid del tid=%d\n", tid);
	return tracerpid_del_tid(tid);
}

static ssize_t OnCmdTracerPidClear(struct ioctl_request *hdr, char __user* buf) {
	(void)hdr;
	(void)buf;
	printk_debug(KERN_INFO "TracerPid clear\n");
	tracerpid_clear_all();
	return 0;
}

static ssize_t OnCmdGetDriverLog(struct ioctl_request *hdr, char __user* buf) {
	unsigned long flags;
	size_t cap = DRIVER_LOG_CAP;
	size_t max_size = (size_t)hdr->param1;
	size_t to_copy;
	size_t start;
	char *tmp;
	if (!buf || max_size == 0)
		return -EINVAL;
	spin_lock_irqsave(&g_driver_log_lock, flags);
	to_copy = g_driver_log_len;
	if (to_copy > max_size)
		to_copy = max_size;
	start = (g_driver_log_head + cap - g_driver_log_len) % cap;
	spin_unlock_irqrestore(&g_driver_log_lock, flags);
	if (to_copy == 0)
		return 0;
	tmp = kmalloc(to_copy, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;
	if (start + to_copy <= cap) {
		memcpy(tmp, g_driver_log_buf + start, to_copy);
	} else {
		size_t first = cap - start;
		memcpy(tmp, g_driver_log_buf + start, first);
		memcpy(tmp + first, g_driver_log_buf, to_copy - first);
	}
	if (x_copy_to_user((void*)buf, tmp, to_copy)) {
		kfree(tmp);
		return -EFAULT;
	}
	kfree(tmp);
	return (ssize_t)to_copy;
}

static ssize_t OnCmdClearDriverLog(struct ioctl_request *hdr, char __user* buf) {
	unsigned long flags;
	(void)hdr;
	(void)buf;
	spin_lock_irqsave(&g_driver_log_lock, flags);
	g_driver_log_head = 0;
	g_driver_log_len = 0;
	memset(g_driver_log_buf, 0, sizeof(g_driver_log_buf));
	spin_unlock_irqrestore(&g_driver_log_lock, flags);
	return 0;
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
	hwbp_handle_info.step_exhausted = false;
	hwbp_handle_info.bp_restore_pending = false;
	hwbp_handle_info.step_remaining = 0;

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
				hwbp_clear_single_step_restore(hwbp_handle_info);
				unreg_task = hwbp_handle_info->task;
				hwbp_handle_info->task = NULL;
				if(hwbp_handle_info->hit_item_arr) {
					cvector_destroy(hwbp_handle_info->hit_item_arr);
					hwbp_handle_info->hit_item_arr = NULL;
				}
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
	/* pc==0 用于取消 hook */
	if (pc == 0) {
		atomic64_set(&g_hook_pc, 0);
		return 0;
	}
	if (pc >= TASK_SIZE) {
		return -EINVAL;
	}
	atomic64_set(&g_hook_pc, pc);
	return 0;
}

static ssize_t OnCmdHideKernelModule(struct ioctl_request *hdr, char __user* buf) {
	return -EOPNOTSUPP;
}

static ssize_t OnCmdSetTraceStepCount(struct ioctl_request *hdr, char __user* buf) {
	size_t count = (size_t)hdr->param1;
	if (count == 0 || count > STEP_LOG_CAPACITY) {
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
		hwbp_clear_all_single_step_restores();
		step_session_start(g_trace_step_count ? g_trace_step_count : 1);
		mutex_lock(&g_hwbp_handle_info_mutex);
		for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
			struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
			mutex_lock(&info->hit_lock);
			info->step_exhausted = false;
			info->step_pending = false;
			mutex_unlock(&info->hit_lock);
		}
		mutex_unlock(&g_hwbp_handle_info_mutex);
		return 0;
	}
	atomic64_set(&g_step_budget_remaining, 0);
	atomic64_set(&g_step_tracked_tid, -1);
	step_session_mark_done(STEP_STOP_MANUAL);
	hwbp_clear_all_single_step_restores();
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
		info->step_exhausted = false;
		mutex_unlock(&info->hit_lock);
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	return 0;
}

static ssize_t OnCmdStartStepSession(struct ioctl_request *hdr, char __user* buf) {
	size_t requested = (size_t)hdr->param1;
	citerator iter;
	if (requested == 0 || requested > STEP_LOG_CAPACITY) {
		return -EINVAL;
	}
	hwbp_clear_all_single_step_restores();
	g_trace_step_count = requested;
	g_simulate_step_enabled = true;
	step_session_start(requested);
	mutex_lock(&g_hwbp_handle_info_mutex);
	for (iter = cvector_begin(g_hwbp_handle_info_arr); iter != cvector_end(g_hwbp_handle_info_arr); iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO *info = (struct HWBP_HANDLE_INFO *)iter;
		mutex_lock(&info->hit_lock);
		info->step_exhausted = false;
		info->step_pending = false;
		info->step_remaining = 0;
		mutex_unlock(&info->hit_lock);
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	return 0;
}

static ssize_t OnCmdSetStepFilter(struct ioctl_request *hdr, char __user* buf) {
	int mode = (int)hdr->param1;
	if (mode != STEP_FILTER_ALL && mode != STEP_FILTER_BRANCH_ONLY) {
		return -EINVAL;
	}
	g_step_filter_mode = mode;
	return 0;
}

static ssize_t OnCmdGetStepStatus(struct ioctl_request *hdr, char __user* buf) {
	unsigned long flags;
	struct STEP_SESSION_STATUS status;
	if (!buf || hdr->buf_size < sizeof(status)) {
		return -EINVAL;
	}
	memset(&status, 0, sizeof(status));
	spin_lock_irqsave(&g_step_log_lock, flags);
	status.running = g_step_session_running ? 1 : 0;
	status.done = g_step_session_done ? 1 : 0;
	status.stop_reason = g_step_stop_reason;
	status.requested_steps = g_step_requested_count;
	status.logged_steps = g_step_log_count;
	status.tracked_tid = (uint64_t)atomic64_read(&g_step_tracked_tid);
	status.next_seq = (uint64_t)atomic64_read(&g_step_seq);
	spin_unlock_irqrestore(&g_step_log_lock, flags);
	if (x_copy_to_user((void*)buf, &status, sizeof(status))) {
		return -EFAULT;
	}
	return (ssize_t)sizeof(status);
}

static ssize_t OnCmdGetStepLog(struct ioctl_request *hdr, char __user* buf) {
	unsigned long flags;
	size_t max_items;
	size_t to_copy;
	struct STEP_LOG_ITEM *tmp;
	size_t size = hdr->buf_size;
	if (!buf || size < sizeof(struct STEP_LOG_ITEM))
		return -EINVAL;
	max_items = size / sizeof(struct STEP_LOG_ITEM);
	spin_lock_irqsave(&g_step_log_lock, flags);
	if (!g_step_session_done) {
		spin_unlock_irqrestore(&g_step_log_lock, flags);
		return -EBUSY;
	}
	to_copy = g_step_log_count;
	if (to_copy > max_items)
		to_copy = max_items;
	if (to_copy == 0) {
		spin_unlock_irqrestore(&g_step_log_lock, flags);
		return 0;
	}

	tmp = kmalloc(sizeof(struct STEP_LOG_ITEM) * to_copy, GFP_KERNEL);
	if (!tmp) {
		spin_unlock_irqrestore(&g_step_log_lock, flags);
		return -ENOMEM;
	}
	memcpy(tmp, g_step_log, sizeof(struct STEP_LOG_ITEM) * to_copy);
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
	case CMD_HWBP_WRITE_PROCESS_MEM:
		return OnCmdWriteProcessMem(hdr, buf);
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
	case CMD_HWBP_SET_TRACE_STEP_COUNT:
		return OnCmdSetTraceStepCount(hdr, buf);
	case CMD_HWBP_SET_STEP_SIMULATE:
		return OnCmdSetStepSimulate(hdr, buf);
	case CMD_HWBP_SET_STEP_FILTER:
		return OnCmdSetStepFilter(hdr, buf);
	case CMD_HWBP_GET_STEP_LOG:
		return OnCmdGetStepLog(hdr, buf);
	case CMD_HWBP_START_STEP_SESSION:
		return OnCmdStartStepSession(hdr, buf);
	case CMD_HWBP_GET_STEP_STATUS:
		return OnCmdGetStepStatus(hdr, buf);
	case CMD_HWBP_SET_TRACERPID_HIDE:
		return OnCmdSetTracerPidHide(hdr, buf);
	case CMD_HWBP_TRACERPID_ADD_TID:
		return OnCmdTracerPidAddTid(hdr, buf);
	case CMD_HWBP_TRACERPID_DEL_TID:
		return OnCmdTracerPidDelTid(hdr, buf);
	case CMD_HWBP_TRACERPID_CLEAR:
		return OnCmdTracerPidClear(hdr, buf);
	case CMD_HWBP_GET_DRIVER_LOG:
		return OnCmdGetDriverLog(hdr, buf);
	case CMD_HWBP_CLEAR_DRIVER_LOG:
		return OnCmdClearDriverLog(hdr, buf);
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
		hwbp_clear_single_step_restore(hwbp_handle_info);
		if (hwbp_handle_info->task) {
			put_task_struct(hwbp_handle_info->task);
			hwbp_handle_info->task = NULL;
		}
		if(hwbp_handle_info->hit_item_arr) {
			cvector_destroy(hwbp_handle_info->hit_item_arr);
			hwbp_handle_info->hit_item_arr = NULL;
		}
		mutex_unlock(&hwbp_handle_info->hit_lock);
		mutex_destroy(&hwbp_handle_info->hit_lock);
	}
	cvector_destroy(g_hwbp_handle_info_arr);
	g_hwbp_handle_info_arr = NULL;
	mutex_unlock(&g_hwbp_handle_info_mutex);
	hwbp_clear_all_single_step_restores();
	
	for (iter = cvector_begin(wait_unregister_bp_arr); iter != cvector_end(wait_unregister_bp_arr); iter = cvector_next(wait_unregister_bp_arr, iter)) {
	  struct perf_event * bp = *(struct perf_event **)iter;
	  x_unregister_hw_breakpoint(bp);
	}
	cvector_destroy(wait_unregister_bp_arr);
}

int hwbp_release(struct inode *inode, struct file *filp) {
	clean_hwbp();
	tracerpid_clear_all();
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
	g_bp_step_hook.fn = hwbp_single_step_restore_hook;
	register_step_hook(&g_bp_step_hook);

#ifdef CONFIG_ANTI_PTRACE_DETECTION_MODE
	start_anti_ptrace_detection(&g_hwbp_handle_info_mutex, &g_hwbp_handle_info_arr);
#endif

	return 0;
}

void hwbp_exit(void) {
#ifdef CONFIG_ANTI_PTRACE_DETECTION_MODE
	stop_anti_ptrace_detection();
#endif
	unregister_step_hook(&g_bp_step_hook);

	clean_hwbp();
	
	mutex_destroy(&g_hwbp_handle_info_mutex);
}
