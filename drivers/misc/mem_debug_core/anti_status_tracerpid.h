#ifndef ANTI_STATUS_TRACERPID_H_
#define ANTI_STATUS_TRACERPID_H_

#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/string.h>

/*
 * Kretprobe on proc_pid_status: rewrite "TracerPid:\tXXXX" to "TracerPid:\t0"
 * and "State:\tX (...)" to "R (running)" for selected tids.
 */

static bool g_status_probe_enabled = false;

struct tracerpid_tid_node {
	pid_t tid;
	struct list_head node;
};

static LIST_HEAD(g_tracerpid_tid_list);
static DEFINE_SPINLOCK(g_tracerpid_lock);
static atomic_t g_tracerpid_count = ATOMIC_INIT(0);

struct status_probe_ctx {
	struct seq_file *m;
	struct task_struct *task;
	int enabled;
};

static void *memmem_safe(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
{
	const char *h = (const char *)haystack;
	size_t i;
	if (!haystack || !needle || needlelen == 0 || haystacklen < needlelen)
		return NULL;
	for (i = 0; i + needlelen <= haystacklen; ++i) {
		if (memcmp(h + i, needle, needlelen) == 0)
			return (void *)(h + i);
	}
	return NULL;
}

/* entry: record task for target tgid */
static bool tracerpid_tid_allowed(pid_t tid)
{
	struct tracerpid_tid_node *n;
	unsigned long flags;
	bool found = false;

	if (atomic_read(&g_tracerpid_count) == 0)
		return false;
	spin_lock_irqsave(&g_tracerpid_lock, flags);
	list_for_each_entry(n, &g_tracerpid_tid_list, node) {
		if (n->tid == tid) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&g_tracerpid_lock, flags);
	return found;
}

static int tracerpid_add_tid(pid_t tid)
{
	struct tracerpid_tid_node *node;
	struct tracerpid_tid_node *n;
	unsigned long flags;
	if (tid <= 0)
		return -EINVAL;
	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;
	node->tid = tid;
	spin_lock_irqsave(&g_tracerpid_lock, flags);
	list_for_each_entry(n, &g_tracerpid_tid_list, node) {
		if (n->tid == tid) {
			spin_unlock_irqrestore(&g_tracerpid_lock, flags);
			kfree(node);
			return 0;
		}
	}
	list_add(&node->node, &g_tracerpid_tid_list);
	atomic_inc(&g_tracerpid_count);
	spin_unlock_irqrestore(&g_tracerpid_lock, flags);
	return 0;
}

static int tracerpid_del_tid(pid_t tid)
{
	struct tracerpid_tid_node *n, *tmp;
	unsigned long flags;
	if (tid <= 0)
		return -EINVAL;
	spin_lock_irqsave(&g_tracerpid_lock, flags);
	list_for_each_entry_safe(n, tmp, &g_tracerpid_tid_list, node) {
		if (n->tid == tid) {
			list_del(&n->node);
			atomic_dec(&g_tracerpid_count);
			spin_unlock_irqrestore(&g_tracerpid_lock, flags);
			kfree(n);
			return 0;
		}
	}
	spin_unlock_irqrestore(&g_tracerpid_lock, flags);
	return 0;
}

static void tracerpid_clear_all(void)
{
	struct tracerpid_tid_node *n, *tmp;
	unsigned long flags;
	spin_lock_irqsave(&g_tracerpid_lock, flags);
	list_for_each_entry_safe(n, tmp, &g_tracerpid_tid_list, node) {
		list_del(&n->node);
		kfree(n);
	}
	atomic_set(&g_tracerpid_count, 0);
	spin_unlock_irqrestore(&g_tracerpid_lock, flags);
}

/* entry: record task for target tid */
static int entry_proc_pid_status(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = NULL;
	struct status_probe_ctx *ctx;

	if (!g_status_probe_enabled || atomic_read(&g_tracerpid_count) == 0)
		return 0;

#if defined(CONFIG_ARM64)
	/* proc_pid_status(struct seq_file *m, struct pid_namespace *ns, struct pid *pid, struct task_struct *task) */
	task = (struct task_struct *)regs->regs[3];
#endif
	ctx = (struct status_probe_ctx *)ri->data;
	ctx->enabled = 0;
	ctx->task = NULL;
	ctx->m = NULL;
	if (!task)
		return 0;
	if (!tracerpid_tid_allowed(task->pid))
		return 0;
	ctx->task = task;
#if defined(CONFIG_ARM64)
	ctx->m = (struct seq_file *)regs->regs[0];
#else
	ctx->m = NULL;
#endif
	ctx->enabled = 1;
	return 0;
}

/* return handler: modify seq_file buffer */
static int ret_proc_pid_status(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task;
	struct seq_file *m;
	char *buf, *p;
	size_t len;
	const char *state_tag = "State:\t";
	const char *state_val = "R (running)";
	size_t state_len = strlen(state_val);

	if (!g_status_probe_enabled)
		return 0;

	task = ((struct status_probe_ctx *)ri->data)->task;
	if (!task || !((struct status_probe_ctx *)ri->data)->enabled)
		return 0;

	m = ((struct status_probe_ctx *)ri->data)->m;
	if (!m || !m->buf || m->count == 0)
		return 0;

	buf = m->buf;
	len = m->count;
	p = memmem_safe(buf, len, "TracerPid:\t", strlen("TracerPid:\t"));
	if (!p)
		return 0;
	p += strlen("TracerPid:\t");
	/* write single '0', pad rest with spaces */
	if (p < buf + len && *p != '\n') {
		*p = '0';
		p++;
	}
	while (p < buf + len && *p != '\n') {
		*p = ' ';
		p++;
	}

	/* force State to running in status output */
	p = memmem_safe(buf, len, state_tag, strlen(state_tag));
	if (p) {
		p += strlen(state_tag);
		/* overwrite with "R (running)" then pad to newline */
		if (p + state_len < buf + len) {
			memcpy(p, state_val, state_len);
			p += state_len;
			while (p < buf + len && *p != '\n') {
				*p = ' ';
				p++;
			}
		}
	}
	return 0;
}

static struct kretprobe g_status_kretprobe = {
	.handler = ret_proc_pid_status,
	.entry_handler = entry_proc_pid_status,
	.maxactive = 20,
};

static bool install_status_probe(void)
{
	int ret;
	if (g_status_probe_enabled)
		return true;
	memset(&g_status_kretprobe, 0, sizeof(g_status_kretprobe));
	g_status_kretprobe.handler = ret_proc_pid_status;
	g_status_kretprobe.entry_handler = entry_proc_pid_status;
	g_status_kretprobe.maxactive = 20;
	g_status_kretprobe.data_size = sizeof(struct status_probe_ctx);
	g_status_kretprobe.kp.symbol_name = "proc_pid_status";
	ret = register_kretprobe(&g_status_kretprobe);
	if (ret) {
		return false;
	}
	g_status_probe_enabled = true;
	return true;
}

static __maybe_unused void uninstall_status_probe(void)
{
	if (!g_status_probe_enabled)
		return;
	unregister_kretprobe(&g_status_kretprobe);
	g_status_probe_enabled = false;
}

#endif /* ANTI_STATUS_TRACERPID_H_ */
