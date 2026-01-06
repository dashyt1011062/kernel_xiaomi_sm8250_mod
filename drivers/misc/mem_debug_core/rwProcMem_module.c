#include "rwProcMem_module.h"
#include "hwbp_module.h"

#include <linux/module.h>

#include <linux/fs.h>

#include <linux/uaccess.h>

#include <linux/ioctl.h>

#define MY_TASK_COMM_LEN 16

#pragma pack(push,1)
struct init_device_info {
	int pid;
	int tgid;
	char my_name[MY_TASK_COMM_LEN + 1];
	char my_auxv[1024];
	int my_auxv_size;
};
struct arg_info {
	uint64_t arg_start;
	uint64_t arg_end;
};
#pragma pack(pop)

static ssize_t OnCmdInitDeviceInfo(struct ioctl_request *hdr, char __user* buf) {
	long err = 0;
	struct init_device_info* pinit_device_info = (struct init_device_info*)x_kmalloc(sizeof(struct init_device_info), GFP_KERNEL);
	if (!pinit_device_info) {
		return -ENOMEM;
	}
	printk_debug(KERN_INFO "CMD_INIT_DEVICE_INFO\n");
	memset(pinit_device_info, 0, sizeof(struct init_device_info));
	if (x_copy_from_user((void*)pinit_device_info, (void*)buf, sizeof(struct init_device_info)) == 0) {
		printk_debug(KERN_INFO "my_name:%s\n", pinit_device_info->my_name);
		printk_debug(KERN_INFO "pid:%d, tgid:%d\n", pinit_device_info->pid, pinit_device_info->tgid);
		printk_debug(KERN_INFO "my_auxv_size:%d\n", pinit_device_info->my_auxv_size);
		
		do {
			err = init_mmap_lock_offset();
			if(err) { break; }
			err = init_map_count_offset();
			if(err) { break; }
			err = init_proc_cmdline_offset(&pinit_device_info->my_auxv[0], pinit_device_info->my_auxv_size);
			if(err) { break; }
			err = init_proc_root_offset(pinit_device_info->my_name);
			if(err) { break; }
			err = init_task_next_offset();
			if(err) { break; }
			err = init_task_pid_offset(pinit_device_info->pid, pinit_device_info->tgid);
		} while(0);
	} else {
		err = -EINVAL;
	}
	kfree(pinit_device_info);
	return err;
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

static ssize_t OnCmdReadProcessMemory(struct ioctl_request *hdr, char __user* buf) {
	struct pid * proc_pid_struct = (struct pid *)hdr->param1;
	size_t proc_virt_addr = (size_t)hdr->param2;
	bool is_force_read = hdr->param3 == 1 ? true : false;
	size_t size = (size_t)hdr->buf_size;
	size_t read_size = 0;

	printk_debug(KERN_INFO "CMD_READ_PROCESS_MEMORY\n");
	printk_debug(KERN_INFO "READ proc_pid_struct*:0x%p,size:%ld\n", (void*)proc_pid_struct, sizeof(proc_pid_struct));
	printk_debug(KERN_INFO "READ proc_virt_addr:0x%zx,size:%ld\n", proc_virt_addr, sizeof(proc_virt_addr));
	printk_debug(KERN_INFO "READ size:%zu force:%d\n", size, is_force_read ? 1 : 0);

	if (is_force_read == false && !check_proc_map_can_read(proc_pid_struct, proc_virt_addr, size)) {
		printk_debug(KERN_INFO "READ check_proc_map_can_read failed\n");
		return -EFAULT;
	}

	while (read_size < size) {
		size_t phy_addr = 0;
		size_t pfn_sz = 0;
		char *lpOutBuf = NULL;
		pte_t *pte;

		bool old_pte_can_read;
		phy_addr = get_proc_phy_addr(proc_pid_struct, proc_virt_addr + read_size, &pte);
		printk_debug(KERN_INFO "calc phy_addr:0x%zx\n", phy_addr);

		if (phy_addr == 0) {
			printk_debug(KERN_INFO "READ get_proc_phy_addr failed at 0x%zx\n", proc_virt_addr + read_size);
			break;
		}

		old_pte_can_read = is_pte_can_read(pte);
		if (is_force_read) {
			if (!old_pte_can_read) {
				if (!change_pte_read_status(pte, true)) {
					printk_debug(KERN_INFO "READ change_pte_read_status enable failed\n");
					break;
				}

			}
		} else if (!old_pte_can_read) {
			printk_debug(KERN_INFO "READ pte not readable and not force\n");
			break;
		} 

		pfn_sz = size_inside_page(phy_addr, ((size - read_size) > PAGE_SIZE) ? PAGE_SIZE : (size - read_size));
		printk_debug(KERN_INFO "pfn_sz:%zu\n", pfn_sz);


		lpOutBuf = (char*)(buf + read_size);
		read_ram_physical_addr(false, phy_addr, lpOutBuf, pfn_sz);

		if (is_force_read && old_pte_can_read == false) {
			change_pte_read_status(pte, false);
		}
		read_size += pfn_sz;
	}
	printk_debug(KERN_INFO "READ done size:%zu\n", read_size);
	return read_size;
}

ssize_t rwpm_force_read_task(struct task_struct *task, size_t proc_virt_addr, void *dst, size_t size) {
	struct pid * proc_pid_struct;
	size_t read_size = 0;
	if (!task || !dst || !proc_virt_addr || size == 0) {
		return -EINVAL;
	}
	proc_pid_struct = task_pid(task);
	if (!proc_pid_struct) {
		return -EINVAL;
	}
	while (read_size < size) {
		size_t phy_addr = 0;
		size_t pfn_sz = 0;
		pte_t *pte;
		bool old_pte_can_read;
		phy_addr = get_proc_phy_addr(proc_pid_struct, proc_virt_addr + read_size, &pte);
		if (phy_addr == 0) {
			break;
		}
		old_pte_can_read = is_pte_can_read(pte);
		if (!old_pte_can_read) {
			if (!change_pte_read_status(pte, true)) {
				break;
			}
		}
		pfn_sz = size_inside_page(phy_addr, ((size - read_size) > PAGE_SIZE) ? PAGE_SIZE : (size - read_size));
		if (read_ram_physical_addr(true, phy_addr, (char*)dst + read_size, pfn_sz) == 0) {
			if (!old_pte_can_read) {
				change_pte_read_status(pte, false);
			}
			break;
		}
		if (!old_pte_can_read) {
			change_pte_read_status(pte, false);
		}
		read_size += pfn_sz;
	}
	return read_size;
}

static ssize_t OnCmdWriteProcessMemory(struct ioctl_request *hdr, char __user* buf) {
	struct pid * proc_pid_struct = (struct pid *)hdr->param1;
	size_t proc_virt_addr = (size_t)hdr->param2;
	bool is_force_write = hdr->param3 == 1 ? true : false;
	size_t size = (size_t)hdr->buf_size;
	size_t write_size = 0;
	printk_debug(KERN_INFO "CMD_WRITE_PROCESS_MEMORY\n");
	printk_debug(KERN_INFO "WRITE proc_pid_struct*:0x%p,size:%ld\n", (void*)proc_pid_struct, sizeof(proc_pid_struct));
	printk_debug(KERN_INFO "WRITE proc_virt_addr:0x%zx,size:%ld\n", proc_virt_addr, sizeof(proc_virt_addr));

	if (is_force_write == false && !check_proc_map_can_write(proc_pid_struct, proc_virt_addr, size)) {
		return -EFAULT;
	}

	while (write_size < size) {
		size_t phy_addr = 0;
		size_t pfn_sz = 0;
		char * input_buf = NULL;

		pte_t *pte;
		bool old_pte_can_write;
		phy_addr = get_proc_phy_addr(proc_pid_struct, proc_virt_addr + write_size, &pte);
		printk_debug(KERN_INFO "phy_addr:0x%zx\n", phy_addr);
		if (phy_addr == 0) {
			break;
		}

		old_pte_can_write = is_pte_can_write(pte);
		if (is_force_write) {
			if (!old_pte_can_write) {
				if (!change_pte_write_status(pte, true)) { break; }
			}
		} else if (!old_pte_can_write) {
			break;
		}

		pfn_sz = size_inside_page(phy_addr, ((size - write_size) > PAGE_SIZE) ? PAGE_SIZE : (size - write_size));
		printk_debug(KERN_INFO "pfn_sz:%zu\n", pfn_sz);

		input_buf = (char*)(((size_t)buf + write_size));
		write_ram_physical_addr(phy_addr, input_buf, false, pfn_sz);
		if (is_force_write && old_pte_can_write == false) {
			change_pte_write_status(pte, false);
		}

		write_size += pfn_sz;
	}
	return write_size;
}

static ssize_t OnCmdGetProcessMapsCount(struct ioctl_request *hdr, char __user* buf) {
	struct pid * proc_pid_struct = (struct pid *)hdr->param1;
	printk_debug(KERN_INFO "CMD_GET_PROCESS_MAPS_COUNT\n");
	printk_debug(KERN_INFO "proc_pid_struct*:0x%p, size:%ld\n", (void*)proc_pid_struct, sizeof(proc_pid_struct));

	return get_proc_map_count(proc_pid_struct);
}

static ssize_t OnCmdGetProcessMapsList(struct ioctl_request *hdr, char __user* buf) {
	struct pid * proc_pid_struct = (struct pid *)hdr->param1;
	printk_debug(KERN_INFO "CMD_GET_PROCESS_MAPS_LIST\n");
	printk_debug(KERN_INFO "proc_pid_struct*:0x%p,size:%ld\n", (void*)proc_pid_struct, sizeof(proc_pid_struct));
	printk_debug(KERN_INFO "buf_size:%llu\n", hdr->buf_size);
	return get_proc_maps_list(false, proc_pid_struct, (void*)(buf), hdr->buf_size - 1);
}

static ssize_t OnCmdCheckProcessPhyAddr(struct ioctl_request *hdr, char __user* buf) {
	struct pid * proc_pid_struct = (struct pid *)hdr->param1;
	size_t proc_virt_addr = (size_t)hdr->param2;
	pte_t *pte;
	printk_debug(KERN_INFO "CMD_CHECK_PROCESS_ADDR_PHY\n");
	printk_debug(KERN_INFO "proc_pid_struct *:0x%p,size:%ld\n", (void*)proc_pid_struct, sizeof(proc_pid_struct));
	printk_debug(KERN_INFO "proc_virt_addr :0x%zx\n", proc_virt_addr);
	if (get_proc_phy_addr(proc_pid_struct, proc_virt_addr, &pte)) {
		return 1;
	}
	return 0;
}

static ssize_t OnCmdGetPidList(struct ioctl_request *hdr, char __user* buf) {
	printk_debug(KERN_INFO "CMD_GET_PID_LIST\n");
	printk_debug(KERN_INFO "buf_size:%llu\n", hdr->buf_size);
	return get_proc_pid_list(false, buf, hdr->buf_size);
}

static ssize_t OnCmdSetProcessRoot(struct ioctl_request *hdr, char __user* buf) {
	struct pid * proc_pid_struct = (struct pid *)hdr->param1;
	printk_debug(KERN_INFO "CMD_SET_PROCESS_ROOT\n");
	printk_debug(KERN_INFO "proc_pid_struct*:0x%p,size:%ld\n", (void*)proc_pid_struct, sizeof(proc_pid_struct));
	return set_process_root(proc_pid_struct);
}

static ssize_t OnCmdGetProcessRss(struct ioctl_request *hdr, char __user* buf) {
	struct pid * proc_pid_struct = (struct pid *)hdr->param1;
	uint64_t rss = 0;
	printk_debug(KERN_INFO "CMD_GET_PROCESS_RSS\n");
	printk_debug(KERN_INFO "proc_pid_struct*:0x%p,size:%ld\n", (void*)proc_pid_struct, sizeof(proc_pid_struct));
	rss = read_proc_rss_size(proc_pid_struct);
	if (!!x_copy_to_user((void*)buf, &rss, sizeof(rss))) {
		return -EINVAL;
	}
	return 0;
}

static ssize_t OnCmdGetProcessCmdlineAddr(struct ioctl_request *hdr, char __user* buf) {
	struct pid * proc_pid_struct = (struct pid *)hdr->param1;
	size_t arg_start = 0, arg_end = 0;
	int res;
	struct arg_info aginfo = {0};
	printk_debug(KERN_INFO "CMD_GET_PROCESS_CMDLINE_ADDR\n");
	printk_debug(KERN_INFO "proc_pid_struct *:0x%p,size:%ld\n", (void*)proc_pid_struct, sizeof(proc_pid_struct));
	res = get_proc_cmdline_addr(proc_pid_struct, &arg_start, &arg_end);
	aginfo.arg_start = (uint64_t)arg_start;
	aginfo.arg_end = (uint64_t)arg_end;
	if (!!x_copy_to_user((void*)buf, &aginfo, sizeof(aginfo))) {
		return -EINVAL;
	}
	return res;
}


static ssize_t OnCmdHideKernelModule(struct ioctl_request *hdr, char __user* buf) {
	return -EOPNOTSUPP;
}


static inline ssize_t DispatchCommand(struct ioctl_request *hdr, char __user* buf) {
	unsigned char cmd = (unsigned char)hdr->cmd;
	if (cmd >= CMD_HWBP_BASE) {
		return hwbp_dispatch(hdr, buf);
	}
	switch (cmd) {
	case CMD_INIT_DEVICE_INFO:
		return OnCmdInitDeviceInfo(hdr, buf);
	case CMD_OPEN_PROCESS:
		return OnCmdOpenProcess(hdr, buf);
	case CMD_READ_PROCESS_MEMORY:
		return OnCmdReadProcessMemory(hdr, buf);
	case CMD_WRITE_PROCESS_MEMORY:
		return OnCmdWriteProcessMemory(hdr, buf);
	case CMD_CLOSE_PROCESS:
		return OnCmdCloseProcess(hdr, buf);
	case CMD_GET_PROCESS_MAPS_COUNT:
		return OnCmdGetProcessMapsCount(hdr, buf);
	case CMD_GET_PROCESS_MAPS_LIST:
		return OnCmdGetProcessMapsList(hdr, buf);
	case CMD_CHECK_PROCESS_ADDR_PHY:
		return OnCmdCheckProcessPhyAddr(hdr, buf);
	case CMD_GET_PID_LIST:
		return OnCmdGetPidList(hdr, buf);
	case CMD_SET_PROCESS_ROOT:
		return OnCmdSetProcessRoot(hdr, buf);
	case CMD_GET_PROCESS_RSS:
		return OnCmdGetProcessRss(hdr, buf);
	case CMD_GET_PROCESS_CMDLINE_ADDR:
		return OnCmdGetProcessCmdlineAddr(hdr, buf);
	case CMD_HIDE_KERNEL_MODULE:
		return OnCmdHideKernelModule(hdr, buf);
	default:
		return -EINVAL;
	}
	return -EINVAL;
}


#define MEM_DEBUG_MAX_PAYLOAD (1024 * 1024)

static long mem_debug_dispatch_buf(void __user *user_buf, size_t total_size)
{
	struct ioctl_request hdr = {0};
	if (!user_buf)
		return -EINVAL;
	if (x_copy_from_user(&hdr, user_buf, sizeof(hdr)))
		return -EFAULT;
	if (hdr.buf_size > MEM_DEBUG_MAX_PAYLOAD)
		return -EINVAL;
	if (total_size && total_size < sizeof(hdr) + hdr.buf_size)
		return -EINVAL;
	return DispatchCommand(&hdr, (char __user *)user_buf + sizeof(hdr));
}

long mem_debug_dispatch(void __user *arg)
{
	return mem_debug_dispatch_buf(arg, 0);
}

static int __init mem_debug_core_init(void)
{
	int ret = hwbp_init();
	if (ret)
		return ret;
	return 0;
}

static void __exit mem_debug_core_exit(void)
{
	hwbp_exit();
}

// Built-in early init
device_initcall(mem_debug_core_init);
