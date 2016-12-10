#include <linux/module.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <asm/unistd.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/string.h>

MODULE_AUTHOR("Ahmed Fekry <nixnub@gmail.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Stealing sys_mkdir syscall");

static int e;
static size_t len;
static void **sys_call_table = NULL;
static const char *my_path = "diva";
static const umode_t my_mode = 777;

static asmlinkage
long (*old_sys_mkdir)(const char __user *pathname, umode_t mode);
static asmlinkage
long fakedir(const char __user *pathname, umode_t mode)
{
	len = strlen(my_path);
	pr_info("[mkdir] [caught] creating diva\n");
	e = copy_to_user((void *)pathname, my_path, len);
	return old_sys_mkdir(pathname, my_mode);
}

static int __init thief_init(void) {

	pr_info("[mkdir] Module loaded\n");
        sys_call_table = (void **)kallsyms_lookup_name("sys_call_table");
	pr_info("loaded syscall table at %p\n", sys_call_table);
	old_sys_mkdir = sys_call_table[__NR_mkdir];
	pr_info("old sys_mkdir saved in *old_sys_mkdir --> %p\n", old_sys_mkdir);
	pr_info("stealing sys_mkdir\n");
	sys_call_table[__NR_mkdir] = fakedir;
	return 0;
}

static void __exit thief_exit(void)
{
	sys_call_table[__NR_mkdir] = old_sys_mkdir;
	pr_info("Module mkdir thief unloaded\n");
}

module_init(thief_init);
module_exit(thief_exit);
