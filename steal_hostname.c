#include <linux/module.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <asm/unistd.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/string.h>

MODULE_AUTHOR("Ahmed Fekry <nixnub@gmail.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Stealing sys_sethostname syscall");

static int e;
static char myname[4] = "diva";
static void **sys_call_table = NULL;
static size_t mylen;

static int (* old_sethostname)(const char *name, size_t len);
static int set_diva(const char *name, size_t len)
{
	mylen = strlen(myname);
	pr_info("caught sethostname, changing it to diva\n");
	e = copy_to_user((void *)name, myname, mylen);
	return old_sethostname(name, mylen);
}

static int __init thief_init(void) {

	pr_info("Module hostname thief loaded\n");
        sys_call_table = (void **)kallsyms_lookup_name("sys_call_table");
	pr_info("loaded syscall table at %p\n", sys_call_table);
	old_sethostname = sys_call_table[__NR_sethostname];
	pr_info("old sethostname() saved in *old_sethostname --> %p\n", old_sethostname);
	pr_info("overriding sethostname()\n");
	sys_call_table[__NR_sethostname] = set_diva;
	return 0;
}

static void __exit thief_exit(void)
{
	sys_call_table[__NR_sethostname] = old_sethostname;
	pr_info("Module hostname thief unloaded\n");
}
module_init(thief_init);
module_exit(thief_exit);
