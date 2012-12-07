#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <asm-generic/resource.h>

#define PROCFS_MAX_SIZE 1024
#define PROCFS_NAME "ksetlimits"

static struct proc_dir_entry *root;
static char procfs_buffer[PROCFS_MAX_SIZE];
static unsigned long procfs_buffer_size = 0;
static char usage[] = "write to me with `<pid>:<limit type>:<value>`\n";

MODULE_LICENSE("GPL");

int 
procfile_read(char *buffer,
	      char **buffer_location,
	      off_t offset, int buffer_length, int *eof, void *data)
{
	int ret;
	
	printk(KERN_INFO "procfile_read (/proc/%s) called\n", PROCFS_NAME);
	
	if (offset > 0) {
		ret  = 0;
	} else {
		memcpy(buffer, usage, sizeof(usage));
		ret = sizeof(usage);
	}

	return ret;
}


int procfile_write(struct file *file, const char *buffer, unsigned long count,
		   void *data)
{
	struct task_struct *task = NULL;
	char *next = NULL;
	struct rlimit new_rlimit;
	unsigned long limit, value;
	pid_t pid;
	struct pid *p;

	printk(KERN_INFO "procfile_write (/proc/%s) called\n", PROCFS_NAME);

	procfs_buffer_size = count;
	if (procfs_buffer_size > PROCFS_MAX_SIZE ) {
		procfs_buffer_size = PROCFS_MAX_SIZE;
	}
	
	if ( copy_from_user(procfs_buffer, buffer, procfs_buffer_size) ) {
		return -EFAULT;
	}
	procfs_buffer[min(count, sizeof(procfs_buffer) - 1)] = 0;

	pid = simple_strtol(procfs_buffer, &next, 0);
	if (*next != ':') {
		count = -EINVAL;
		goto out;
	}
	next++;

	p = find_get_pid(pid);
	if (p == NULL) {
		count  = -EINVAL;
		goto out;
	}
	task = pid_task(p, PIDTYPE_PID);
	if (p == NULL) {
		count = -EINVAL;
		goto out;
	}


	limit = simple_strtoul(next, &next, 0);
	if (*next != ':' || limit >= RLIM_NLIMITS) {
		count = -EINVAL;
		goto out;
	}
	next++;

	value = simple_strtoul(next, &next, 0);
	if (*next != '\n') {
		count = -EINVAL;
		goto out;
	}

	new_rlimit.rlim_cur = value;
	new_rlimit.rlim_max = value;

	task_lock(task->group_leader);
	task->signal->rlim[limit] = new_rlimit;
	task_unlock(task->group_leader);
out:
	return count;
}


int init_module()
{
	/* create the /proc file */
	root = create_proc_entry(PROCFS_NAME, 0644, NULL);
	
	if (root == NULL) {
		remove_proc_entry(PROCFS_NAME, NULL);
		printk(KERN_ALERT "Error: Could not initialize /proc/%s\n",
		       PROCFS_NAME);
		return -ENOMEM;
	}

	root->read_proc  = procfile_read;
	root->write_proc = procfile_write;
	root->mode   = S_IFREG | S_IRUGO;
	root->uid   = 0;
	root->gid   = 0;
	root->size   = 37;

	printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);
	return 0;
}

void cleanup_module()
{
	remove_proc_entry(PROCFS_NAME, NULL);
	printk(KERN_INFO "/proc/%s removed\n", PROCFS_NAME);
}
