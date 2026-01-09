#ifndef ANTI_STATUS_TRACERPID_H_
#define ANTI_STATUS_TRACERPID_H_

#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/string.h>

/*
 * Kretprobe on proc_pid_status: rewrite "TracerPid:\tXXXX" to "TracerPid:\t0"
 * for a specific tgid (target pid). Default disabled (target_pid=0).
 */

static pid_t g_target_status_pid = 0;
static bool g_status_probe_enabled = false;

/* entry: record task for target tgid */
static int entry_proc_pid_status(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = NULL;

	if (!g_status_probe_enabled || g_target_status_pid == 0)
		return 0;

#if defined(CONFIG_ARM64)
	/* proc_pid_status(struct seq_file *m, struct pid_namespace *ns, struct pid *pid, struct task_struct *task) */
	task = (struct task_struct *)regs->regs[3];
#endif
	if (!task || task->tgid != g_target_status_pid)
		return 0;

	*(struct task_struct **)ri->data = task;
	return 0;
}

/* return handler: modify seq_file buffer */
static int ret_proc_pid_status(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task;
	struct seq_file *m;
	char *buf, *p;
	size_t len;

	if (!g_status_probe_enabled || g_target_status_pid == 0)
		return 0;

	task = *(struct task_struct **)ri->data;
	if (!task || task->tgid != g_target_status_pid)
		return 0;

#if defined(CONFIG_ARM64)
	/* On kretprobe return, x0 holds struct seq_file * */
	m = (struct seq_file *)regs->regs[0];
#else
	m = NULL;
#endif
	if (!m || !m->buf || m->count == 0)
		return 0;

	buf = m->buf;
	len = m->count;
	p = strstr(buf, "TracerPid:\t");
	if (!p)
		return 0;
	p += strlen("TracerPid:\t");
	while (p < buf + len && *p != '\n') {
		if (*p >= '0' && *p <= '9')
			*p = '0';
		p++;
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
	g_status_kretprobe.data_size = sizeof(struct task_struct *);
	g_status_kretprobe.kp.symbol_name = "proc_pid_status";
	ret = register_kretprobe(&g_status_kretprobe);
	if (ret) {
		return false;
	}
	g_status_probe_enabled = true;
	return true;
}

static void uninstall_status_probe(void)
{
	if (!g_status_probe_enabled)
		return;
	unregister_kretprobe(&g_status_kretprobe);
	g_status_probe_enabled = false;
}

#endif /* ANTI_STATUS_TRACERPID_H_ */
