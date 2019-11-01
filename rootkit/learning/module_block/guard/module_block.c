#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/uaccess.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <net/tcp.h>

MODULE_LICENSE("GPL");
//------------------------block modulues-----------------------//
int module_notifier(struct notifier_block *nb, \
					unsigned long action, void *data);
struct notifier_block nb = {
	.notifier_call = module_notifier,
	.priority = INT_MAX
};

int fake_init(void);
void fake_exit(void);

int module_notifier(struct notifier_block *nb, \
					unsigned long action, void *data){
	struct module *module;
	unsigned long flags;
	// definite lock
	DEFINE_SPINLOCK(module_notifier_spinlock);
	module = data;

	// store interrupt, lock
	spin_lock_irqsave(&module_notifier_spinlock, flags);
	switch(module->state){
	case MODULE_STATE_COMING:
		module->init = fake_init;
		module->exit = fake_exit;
		break;
	default:
		break;
	}
	spin_unlock_irqrestore(&module_notifier_spinlock, flags);
	return NOTIFY_DONE;
}

int fake_init(void){
        printk("%s\n", "Fake init.");//for testing
	return 0;
}

void fake_exit(void){
	 printk("%s\n", "Fake exit.");// for testing
	return;
}
//-----------------------block modules end-----------------------//
static int lkm_init(void){
//---------------------- block other module ->
	register_module_notifier(&nb);
	printk("%s\n","module_block loaded");
    	return 0;
}
static void lkm_exit(void){
//---------------------- block other module ->

	unregister_module_notifier(&nb);
	printk("%s\n","module_block unloaded");
	return;
}

module_init(lkm_init);
module_exit(lkm_exit);
